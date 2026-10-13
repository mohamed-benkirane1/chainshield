"""Read-only Ethereum mainnet provider over JSON-RPC.

The RPC endpoint is taken from configuration only (no hard-coded default).
It is never included in error messages or in the provider's repr, since
hosted RPC URLs usually embed an API key.
"""

import itertools
import os
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from eth_utils import keccak

from app.domain.analysis_input import (
    Network,
    normalize_ethereum_address,
    normalize_transaction_hash,
)
from app.domain.token_transfer import NormalizedTokenTransfer
from app.domain.usdt_registry import ContractMatch, check_usdt_contract, get_usdt_contract
from app.providers.base import (
    ChainMismatchError,
    ExecutionResultUnknownError,
    MalformedResponseError,
    NativeUnit,
    NormalizedTransaction,
    ProviderConfigurationError,
    ReceiptUnavailableError,
    RpcError,
    TransactionNotFoundError,
    TransactionPendingError,
    TransactionStatus,
)
from app.providers.transport import JsonRpcTransport, UrllibTransport

RPC_URL_ENV_VAR = "CHAINSHIELD_ETHEREUM_RPC_URL"
ETHEREUM_MAINNET_CHAIN_ID = 1
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_BLOCK_TIMESTAMP = 2**64 - 1  # uint64 in the block header

# keccak256("Transfer(address,address,uint256)"), the ERC-20 Transfer topic.
ERC20_TRANSFER_TOPIC = "0x" + keccak(text="Transfer(address,address,uint256)").hex()

_QUANTITY_RE = re.compile(r"0x[0-9a-fA-F]{1,64}")
_WORD_RE = re.compile(r"0x[0-9a-fA-F]{64}")  # one 32-byte ABI word
_ADDRESS_PADDING = "0" * 24  # 12 zero bytes before a 20-byte address


def _parse_quantity(value: object, field: str) -> int:
    """Parse a JSON-RPC hex quantity exactly (arbitrary precision, no float)."""
    if not isinstance(value, str) or not _QUANTITY_RE.fullmatch(value):
        raise MalformedResponseError(f"invalid {field} in RPC response")
    return int(value, 16)


def _parse_hash(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedResponseError(f"invalid {field} in RPC response")
    try:
        return normalize_transaction_hash(Network.ETHEREUM, value)
    except ValueError:
        raise MalformedResponseError(f"invalid {field} in RPC response") from None


def _parse_address(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedResponseError(f"invalid {field} in RPC response")
    try:
        return normalize_ethereum_address(value)
    except ValueError:
        raise MalformedResponseError(f"invalid {field} in RPC response") from None


def _require_object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MalformedResponseError(f"{what} is not a JSON object")
    return value


def _parse_word(value: object, field: str) -> str:
    """Parse a 32-byte hex word (topic or uint256 data), lowercased."""
    if not isinstance(value, str) or not _WORD_RE.fullmatch(value):
        raise MalformedResponseError(f"invalid {field} in RPC response")
    return value.lower()


def _word_to_address(word: str, field: str) -> str:
    """Decode an indexed address topic: 12 zero bytes then 20 address bytes."""
    if word[2:26] != _ADDRESS_PADDING:
        raise MalformedResponseError(f"{field} topic is not a zero-padded address")
    return normalize_ethereum_address("0x" + word[26:])


def decode_usdt_transfer_logs(
    logs: list[Any], tx_hash: str, block_number: int, block_hash: str
) -> list[NormalizedTokenTransfer]:
    """Decode the official USDT ``Transfer`` events of a successful receipt.

    Every log's metadata is checked against the transaction (hash, block,
    strictly increasing logIndex, not removed by a reorg). Logs from other
    contracts are ignored even if they mimic ``Transfer``; other USDT events
    are ignored. An official USDT ``Transfer`` that is malformed raises
    ``MalformedResponseError`` instead of being skipped or patched. Events
    are returned in log order, one entry per event (amounts are not summed).
    """
    usdt = get_usdt_contract(Network.ETHEREUM)
    transfers: list[NormalizedTokenTransfer] = []
    previous_index = -1
    for log in logs:
        log = _require_object(log, "receipt log")
        if log.get("removed", False) is not False:
            raise MalformedResponseError("receipt contains a log removed by a reorg")
        log_index = _parse_quantity(log.get("logIndex"), "log index")
        if log_index <= previous_index:
            raise MalformedResponseError("receipt logs are not in log index order")
        previous_index = log_index
        if (
            _parse_hash(log.get("transactionHash"), "log transaction hash") != tx_hash
            or _parse_hash(log.get("blockHash"), "log block hash") != block_hash
            or _parse_quantity(log.get("blockNumber"), "log block number") != block_number
        ):
            raise MalformedResponseError("log does not match the transaction")
        emitter = _parse_address(log.get("address"), "log address")
        topics = log.get("topics")
        if not isinstance(topics, list):
            raise MalformedResponseError("invalid log topics in RPC response")

        # Identify USDT by emitting contract only, never by name or symbol.
        if check_usdt_contract(Network.ETHEREUM, emitter) is not ContractMatch.MATCH:
            continue
        words = [_parse_word(topic, "log topic") for topic in topics]
        if not words or words[0] != ERC20_TRANSFER_TOPIC:
            continue  # another USDT event (Approval, ...)
        if len(words) != 3:
            raise MalformedResponseError("USDT Transfer log must have exactly 3 topics")
        transfers.append(
            NormalizedTokenTransfer(
                network=Network.ETHEREUM,
                tx_hash=tx_hash,
                token_symbol=usdt.token,
                token_contract=usdt.contract_address,
                from_address=_word_to_address(words[1], "sender"),
                to_address=_word_to_address(words[2], "recipient"),
                amount_atomic=int(_parse_word(log.get("data"), "log data"), 16),
                decimals=usdt.decimals,
                log_index=log_index,
            )
        )
    return transfers


class EthereumProvider:
    network = Network.ETHEREUM

    def __init__(
        self,
        rpc_url: str,
        *,
        transport: JsonRpcTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        parts = urlsplit(rpc_url) if isinstance(rpc_url, str) else None
        if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
            raise ProviderConfigurationError(
                f"{RPC_URL_ENV_VAR} must be an http(s) URL with a host"
            )
        if not timeout > 0:
            raise ProviderConfigurationError("timeout must be positive")
        self._rpc_url = rpc_url
        self._transport = transport if transport is not None else UrllibTransport()
        self._timeout = timeout
        self._request_ids = itertools.count(1)
        self._chain_verified = False

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        transport: JsonRpcTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> "EthereumProvider":
        env = os.environ if environ is None else environ
        rpc_url = env.get(RPC_URL_ENV_VAR, "").strip()
        if not rpc_url:
            raise ProviderConfigurationError(f"{RPC_URL_ENV_VAR} is not set")
        return cls(rpc_url, transport=transport, timeout=timeout)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(network={self.network.value!r})"

    def get_transaction(self, tx_hash: str) -> NormalizedTransaction:
        tx_hash = normalize_transaction_hash(Network.ETHEREUM, tx_hash)
        self._ensure_mainnet()

        tx = self._fetch_transaction(tx_hash)
        if tx is None:
            return NormalizedTransaction(
                network=self.network, tx_hash=tx_hash, status=TransactionStatus.NOT_FOUND
            )
        if "to" not in tx:
            raise MalformedResponseError("invalid recipient in RPC response")
        from_address = _parse_address(tx.get("from"), "sender")
        to_address = None if tx["to"] is None else _parse_address(tx["to"], "recipient")
        native_value_atomic = _parse_quantity(tx.get("value"), "value")

        if tx.get("blockNumber") is None:
            return NormalizedTransaction(
                network=self.network,
                tx_hash=tx_hash,
                status=TransactionStatus.PENDING,
                from_address=from_address,
                to_address=to_address,
                native_value_atomic=native_value_atomic,
                native_unit=NativeUnit.WEI,
            )

        block_number = _parse_quantity(tx["blockNumber"], "block number")
        block_hash = _parse_hash(tx.get("blockHash"), "block hash")
        status = self._fetch_status(tx_hash, block_number, block_hash)
        block_timestamp = self._fetch_block_timestamp(block_number, block_hash)

        return NormalizedTransaction(
            network=self.network,
            tx_hash=tx_hash,
            status=status,
            from_address=from_address,
            to_address=to_address,
            native_value_atomic=native_value_atomic,
            native_unit=NativeUnit.WEI,
            block_number=block_number,
            block_timestamp=block_timestamp,
        )

    def get_usdt_transfers(self, tx_hash: str) -> list[NormalizedTokenTransfer]:
        """Return the official USDT transfers executed by a transaction.

        ``[]`` means the transaction executed (or reverted) without any
        official USDT ``Transfer`` event. Raises ``TransactionNotFoundError``
        or ``TransactionPendingError`` when there is no executed transaction,
        ``ReceiptUnavailableError`` when its receipt is not available yet and
        ``ExecutionResultUnknownError`` when the receipt has no status.
        """
        tx_hash = normalize_transaction_hash(Network.ETHEREUM, tx_hash)
        self._ensure_mainnet()

        tx = self._fetch_transaction(tx_hash)
        if tx is None:
            raise TransactionNotFoundError("transaction is unknown to the node")
        if tx.get("blockNumber") is None:
            raise TransactionPendingError("transaction is not yet included in a block")
        block_number = _parse_quantity(tx["blockNumber"], "block number")
        block_hash = _parse_hash(tx.get("blockHash"), "block hash")

        status, receipt = self._fetch_receipt(tx_hash, block_number, block_hash)
        if status is None:
            raise ExecutionResultUnknownError("receipt does not state the execution outcome")
        logs = receipt.get("logs")
        if not isinstance(logs, list):
            raise MalformedResponseError("invalid receipt logs in RPC response")
        if status is TransactionStatus.REVERTED:
            # A reverted execution discards its events: nothing was transferred.
            if logs:
                raise MalformedResponseError("reverted transaction receipt has logs")
            return []
        return decode_usdt_transfer_logs(logs, tx_hash, block_number, block_hash)

    def _ensure_mainnet(self) -> None:
        if self._chain_verified:
            return
        chain_id = _parse_quantity(self._call("eth_chainId", []), "chain ID")
        if chain_id != ETHEREUM_MAINNET_CHAIN_ID:
            raise ChainMismatchError(
                f"expected Ethereum mainnet (chain ID {ETHEREUM_MAINNET_CHAIN_ID}), "
                f"got chain ID {chain_id}"
            )
        self._chain_verified = True

    def _fetch_transaction(self, tx_hash: str) -> dict[str, Any] | None:
        """Return the validated transaction object, or None if unknown."""
        tx = self._call("eth_getTransactionByHash", [tx_hash])
        if tx is None:
            return None
        tx = _require_object(tx, "transaction")
        if _parse_hash(tx.get("hash"), "transaction hash") != tx_hash:
            raise MalformedResponseError("RPC returned a different transaction")
        return tx

    def _fetch_receipt(
        self, tx_hash: str, block_number: int, block_hash: str
    ) -> tuple[TransactionStatus | None, dict[str, Any]]:
        """Return the receipt's status (None if absent) and the receipt itself."""
        receipt = self._call("eth_getTransactionReceipt", [tx_hash])
        if receipt is None:
            raise ReceiptUnavailableError(
                "receipt of a mined transaction is not available yet; retry later"
            )
        receipt = _require_object(receipt, "receipt")
        if (
            _parse_hash(receipt.get("transactionHash"), "receipt hash") != tx_hash
            or _parse_hash(receipt.get("blockHash"), "receipt block hash") != block_hash
            or _parse_quantity(receipt.get("blockNumber"), "receipt block number")
            != block_number
        ):
            raise MalformedResponseError("receipt does not match the transaction")
        if receipt.get("status") is None:
            # Pre-Byzantium receipts have no status.
            return None, receipt
        status = _parse_quantity(receipt["status"], "receipt status")
        if status == 1:
            return TransactionStatus.SUCCESS, receipt
        if status == 0:
            return TransactionStatus.REVERTED, receipt
        raise MalformedResponseError("invalid receipt status in RPC response")

    def _fetch_status(
        self, tx_hash: str, block_number: int, block_hash: str
    ) -> TransactionStatus:
        status, _ = self._fetch_receipt(tx_hash, block_number, block_hash)
        if status is None:
            # Do not guess an outcome.
            raise MalformedResponseError("receipt has no execution status")
        return status

    def _fetch_block_timestamp(self, block_number: int, block_hash: str) -> int:
        block = self._call("eth_getBlockByNumber", [hex(block_number), False])
        if block is None:
            raise MalformedResponseError("block of a mined transaction is unavailable")
        block = _require_object(block, "block")
        if (
            _parse_hash(block.get("hash"), "block hash") != block_hash
            or _parse_quantity(block.get("number"), "block number") != block_number
        ):
            raise MalformedResponseError("block does not match the transaction")
        # Ethereum block timestamps are already Unix seconds.
        timestamp = _parse_quantity(block.get("timestamp"), "block timestamp")
        if timestamp > MAX_BLOCK_TIMESTAMP:
            raise MalformedResponseError("invalid block timestamp in RPC response")
        return timestamp

    def _call(self, method: str, params: list[Any]) -> Any:
        request_id = next(self._request_ids)
        response = self._transport.post_json(
            self._rpc_url,
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            self._timeout,
        )
        response = _require_object(response, "RPC response")
        response_id = response.get("id")
        if (
            response.get("jsonrpc") != "2.0"
            or type(response_id) is not int  # reject bools, which compare equal to 1
            or response_id != request_id
        ):
            raise MalformedResponseError(f"invalid JSON-RPC envelope for {method}")
        if "error" in response:
            error = response["error"]
            raise RpcError(method, error.get("code") if isinstance(error, dict) else None)
        if "result" not in response:
            raise MalformedResponseError(f"JSON-RPC response for {method} has no result")
        return response["result"]
