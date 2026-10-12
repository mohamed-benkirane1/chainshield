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

from app.domain.analysis_input import (
    Network,
    normalize_ethereum_address,
    normalize_transaction_hash,
)
from app.providers.base import (
    ChainMismatchError,
    MalformedResponseError,
    NativeUnit,
    NormalizedTransaction,
    ProviderConfigurationError,
    ReceiptUnavailableError,
    RpcError,
    TransactionStatus,
)
from app.providers.transport import JsonRpcTransport, UrllibTransport

RPC_URL_ENV_VAR = "CHAINSHIELD_ETHEREUM_RPC_URL"
ETHEREUM_MAINNET_CHAIN_ID = 1
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_BLOCK_TIMESTAMP = 2**64 - 1  # uint64 in the block header

_QUANTITY_RE = re.compile(r"0x[0-9a-fA-F]{1,64}")


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

        tx = self._call("eth_getTransactionByHash", [tx_hash])
        if tx is None:
            return NormalizedTransaction(
                network=self.network, tx_hash=tx_hash, status=TransactionStatus.NOT_FOUND
            )
        tx = _require_object(tx, "transaction")
        if _parse_hash(tx.get("hash"), "transaction hash") != tx_hash:
            raise MalformedResponseError("RPC returned a different transaction")
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

    def _fetch_status(
        self, tx_hash: str, block_number: int, block_hash: str
    ) -> TransactionStatus:
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
            # Pre-Byzantium receipts have no status; do not guess an outcome.
            raise MalformedResponseError("receipt has no execution status")
        status = _parse_quantity(receipt["status"], "receipt status")
        if status == 1:
            return TransactionStatus.SUCCESS
        if status == 0:
            return TransactionStatus.REVERTED
        raise MalformedResponseError("invalid receipt status in RPC response")

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
