"""Read-only TRON provider over the official java-tron HTTP API.

Lookups use three endpoints, all with hex (``visible: false``) addresses:

* ``/wallet/gettransactionbyid`` (full node): is the transaction known at all?
* ``/walletsolidity/gettransactionbyid``: is it solidified (irreversible)?
* ``/walletsolidity/gettransactioninfobyid``: block and execution result.

Status mapping:

* unknown to the full node -> ``not_found``. These endpoints only see
  transactions included in blocks, so ``pending`` is never reported: a
  transaction still in the mempool is also ``not_found``.
* known to the full node but not solidified -> ``unconfirmed``; its
  execution outcome is not reported until it is final.
* solidified -> ``success`` / ``reverted`` from the execution result, or
  ``ExecutionResultUnknownError`` when that result is not established.

Network limits: the TRON HTTP API exposes no chain identifier comparable to
Ethereum's ``eth_chainId``. This provider does NOT verify that the
configured endpoint serves mainnet; a well-formed answer is not proof of it.
Pointing CHAINSHIELD_TRON_RPC_URL at a mainnet node is the operator's
responsibility.

The endpoint URL and the optional API key never appear in errors or repr.
"""

import os
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import base58
from eth_utils import keccak

from app.domain.analysis_input import (
    Network,
    normalize_transaction_hash,
    validate_tron_address,
)
from app.domain.token_transfer import NormalizedTokenTransfer
from app.domain.usdt_registry import ContractMatch, check_usdt_contract, get_usdt_contract
from app.providers.base import (
    ExecutionResultUnknownError,
    MalformedResponseError,
    NativeUnit,
    NormalizedTransaction,
    ProviderConfigurationError,
    ProviderError,
    ReceiptUnavailableError,
    TransactionNotFoundError,
    TransactionStatus,
    TransactionUnconfirmedError,
    UnsupportedTransactionError,
)
from app.providers.transport import JsonRpcTransport, UrllibTransport

RPC_URL_ENV_VAR = "CHAINSHIELD_TRON_RPC_URL"
API_KEY_ENV_VAR = "CHAINSHIELD_TRON_API_KEY"
API_KEY_HEADER = "TRON-PRO-API-KEY"
DEFAULT_TIMEOUT_SECONDS = 10.0

GET_TRANSACTION_PATH = "/wallet/gettransactionbyid"
GET_SOLID_TRANSACTION_PATH = "/walletsolidity/gettransactionbyid"
GET_SOLID_TRANSACTION_INFO_PATH = "/walletsolidity/gettransactioninfobyid"

TRANSFER_CONTRACT = "TransferContract"
TRIGGER_SMART_CONTRACT = "TriggerSmartContract"
_TYPE_URL_PREFIX = "type.googleapis.com/protocol."

MAX_INT64 = 2**63 - 1  # amounts, block numbers and timestamps are int64

# Transaction.Result.contractResult values that mean execution failed.
_FAILED_CONTRACT_RESULTS = frozenset(
    {
        "REVERT",
        "BAD_JUMP_DESTINATION",
        "OUT_OF_MEMORY",
        "PRECOMPILED_CONTRACT",
        "STACK_TOO_SMALL",
        "STACK_TOO_LARGE",
        "ILLEGAL_OPERATION",
        "STACK_OVERFLOW",
        "OUT_OF_ENERGY",
        "OUT_OF_TIME",
        "JVM_STACK_OVER_FLOW",
        "TRANSFER_FAILED",
        "INVALID_CODE",
    }
)

_HEX_ADDRESS_RE = re.compile(r"41[0-9a-fA-F]{40}")
# Event logs (TransactionInfo.log) use bare hex: 20-byte address without the
# 41 prefix, 32-byte topics and data words without 0x.
_LOG_ADDRESS_RE = re.compile(r"[0-9a-fA-F]{40}")
_LOG_WORD_RE = re.compile(r"[0-9a-fA-F]{64}")
_ADDRESS_PADDING = "0" * 24  # 12 zero bytes before a 20-byte address

# keccak256("Transfer(address,address,uint256)"), the TRC-20 Transfer topic.
TRC20_TRANSFER_TOPIC = keccak(text="Transfer(address,address,uint256)").hex()
_API_KEY_RE = re.compile(r"[\x21-\x7e]{1,256}")  # visible ASCII, no whitespace


class TronApiError(ProviderError):
    """The TRON node answered HTTP 200 with an error payload.

    The node's message is not included: it may echo request details.
    """


def _require_object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MalformedResponseError(f"{what} is not a JSON object")
    return value


def _parse_int(value: object, field: str) -> int:
    """Accept only JSON integers (no floats, bools or strings) within int64."""
    if type(value) is not int or not 0 <= value <= MAX_INT64:
        raise MalformedResponseError(f"invalid {field} in TRON response")
    return value


def _parse_tx_id(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedResponseError(f"invalid {field} in TRON response")
    try:
        return normalize_transaction_hash(Network.TRON, value)
    except ValueError:
        raise MalformedResponseError(f"invalid {field} in TRON response") from None


def hex_to_base58_address(value: object, field: str = "address") -> str:
    """Convert a hex ``41...`` TRON address (21 bytes) to Base58Check."""
    if not isinstance(value, str) or not _HEX_ADDRESS_RE.fullmatch(value):
        raise MalformedResponseError(f"invalid {field} in TRON response")
    # The regex guarantees the 0x41 prefix and the 21-byte length.
    raw = bytes.fromhex(value)
    return validate_tron_address(base58.b58encode_check(raw).decode("ascii"))


def _parse_log_word(value: object, field: str) -> str:
    if not isinstance(value, str) or not _LOG_WORD_RE.fullmatch(value):
        raise MalformedResponseError(f"invalid {field} in TRON response")
    return value.lower()


def _log_word_to_address(word: str, field: str) -> str:
    """Decode an indexed address topic: 12 zero bytes then 20 address bytes."""
    if word[:24] != _ADDRESS_PADDING:
        raise MalformedResponseError(f"{field} topic is not a zero-padded address")
    return hex_to_base58_address("41" + word[24:], field)


def decode_usdt_transfer_logs(logs: list[Any], tx_hash: str) -> list[NormalizedTokenTransfer]:
    """Decode the official USDT ``Transfer`` events of a solidified receipt.

    Logs from other contracts are ignored even if they mimic ``Transfer``;
    other USDT events are ignored. An official USDT ``Transfer`` that is
    malformed raises ``MalformedResponseError``. TRON logs carry no index, so
    ``log_index`` is ``None`` and the list keeps the emission order.
    """
    usdt = get_usdt_contract(Network.TRON)
    transfers: list[NormalizedTokenTransfer] = []
    for log in logs:
        log = _require_object(log, "receipt log")
        address = log.get("address")
        if not isinstance(address, str) or not _LOG_ADDRESS_RE.fullmatch(address):
            raise MalformedResponseError("invalid log address in TRON response")
        emitter = hex_to_base58_address("41" + address, "log address")
        topics = log.get("topics", [])  # proto3 JSON omits empty lists
        if not isinstance(topics, list):
            raise MalformedResponseError("invalid log topics in TRON response")

        # Identify USDT by emitting contract only, never by name or symbol.
        if check_usdt_contract(Network.TRON, emitter) is not ContractMatch.MATCH:
            continue
        words = [_parse_log_word(topic, "log topic") for topic in topics]
        if not words or words[0] != TRC20_TRANSFER_TOPIC:
            continue  # another USDT event (Approval, ...)
        if len(words) != 3:
            raise MalformedResponseError("USDT Transfer log must have exactly 3 topics")
        transfers.append(
            NormalizedTokenTransfer(
                network=Network.TRON,
                tx_hash=tx_hash,
                token_symbol=usdt.token,
                token_contract=usdt.contract_address,
                from_address=_log_word_to_address(words[1], "sender"),
                to_address=_log_word_to_address(words[2], "recipient"),
                amount_atomic=int(_parse_log_word(log.get("data"), "log data"), 16),
                decimals=usdt.decimals,
                log_index=None,
            )
        )
    return transfers


class TronProvider:
    network = Network.TRON

    def __init__(
        self,
        rpc_url: str,
        *,
        api_key: str | None = None,
        transport: JsonRpcTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        parts = urlsplit(rpc_url) if isinstance(rpc_url, str) else None
        if (
            parts is None
            or parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.query
            or parts.fragment
        ):
            raise ProviderConfigurationError(
                f"{RPC_URL_ENV_VAR} must be an http(s) base URL with a host "
                "and no query or fragment"
            )
        if api_key is not None and (
            not isinstance(api_key, str) or not _API_KEY_RE.fullmatch(api_key)
        ):
            raise ProviderConfigurationError(f"{API_KEY_ENV_VAR} has an invalid format")
        if not timeout > 0:
            raise ProviderConfigurationError("timeout must be positive")
        self._base_url = rpc_url.rstrip("/")
        self._headers = {API_KEY_HEADER: api_key} if api_key is not None else {}
        self._transport = transport if transport is not None else UrllibTransport()
        self._timeout = timeout

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        transport: JsonRpcTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> "TronProvider":
        env = os.environ if environ is None else environ
        rpc_url = env.get(RPC_URL_ENV_VAR, "").strip()
        if not rpc_url:
            raise ProviderConfigurationError(f"{RPC_URL_ENV_VAR} is not set")
        api_key = env.get(API_KEY_ENV_VAR, "").strip() or None
        return cls(rpc_url, api_key=api_key, transport=transport, timeout=timeout)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(network={self.network.value!r})"

    def get_transaction(self, tx_hash: str) -> NormalizedTransaction:
        return self._lookup(tx_hash)[0]

    def get_usdt_transfers(self, tx_hash: str) -> list[NormalizedTokenTransfer]:
        """Return the official USDT transfers executed by a solidified transaction.

        ``[]`` means the transaction executed (or reverted) without any
        official USDT ``Transfer`` event. Raises ``TransactionNotFoundError``
        or ``TransactionUnconfirmedError`` when there is no final execution,
        and the errors of ``get_transaction`` otherwise (receipt unavailable,
        unknown execution result, unsupported contract type...).
        """
        tx, info = self._lookup(tx_hash)
        if tx.status is TransactionStatus.NOT_FOUND:
            raise TransactionNotFoundError("transaction is unknown to the node")
        if tx.status is TransactionStatus.UNCONFIRMED or info is None:
            raise TransactionUnconfirmedError("transaction is not solidified yet")
        logs = info.get("log", [])  # proto3 JSON omits an empty log list
        if not isinstance(logs, list):
            raise MalformedResponseError("invalid receipt logs in TRON response")
        if tx.status is TransactionStatus.REVERTED:
            # A reverted execution discards its events: nothing was transferred.
            if logs:
                raise MalformedResponseError("reverted transaction receipt has logs")
            return []
        return decode_usdt_transfer_logs(logs, tx.tx_hash)

    def _lookup(self, tx_hash: str) -> tuple[NormalizedTransaction, dict[str, Any] | None]:
        """Look up a transaction; also return its solidified info, if any."""
        tx_hash = normalize_transaction_hash(Network.TRON, tx_hash)

        tx = self._post(GET_TRANSACTION_PATH, tx_hash)
        if not tx:
            return NormalizedTransaction(
                network=self.network, tx_hash=tx_hash, status=TransactionStatus.NOT_FOUND
            ), None
        self._check_tx_id(tx, tx_hash)

        solid_tx = self._post(GET_SOLID_TRANSACTION_PATH, tx_hash)
        if not solid_tx:
            _, from_address, to_address, native_value = self._parse_contract(tx)
            return NormalizedTransaction(
                network=self.network,
                tx_hash=tx_hash,
                status=TransactionStatus.UNCONFIRMED,
                from_address=from_address,
                to_address=to_address,
                native_value_atomic=native_value,
                native_unit=NativeUnit.SUN,
            ), None
        self._check_tx_id(solid_tx, tx_hash)
        if solid_tx.get("raw_data") != tx.get("raw_data"):
            raise MalformedResponseError("full and solidity nodes disagree on the transaction")
        contract_type, from_address, to_address, native_value = self._parse_contract(
            solid_tx
        )

        info = self._post(GET_SOLID_TRANSACTION_INFO_PATH, tx_hash)
        if not info:
            raise ReceiptUnavailableError(
                "execution info of a solidified transaction is not available yet; "
                "retry later"
            )
        if _parse_tx_id(info.get("id"), "transaction info id") != tx_hash:
            raise MalformedResponseError("TRON returned info for a different transaction")
        block_number = _parse_int(info.get("blockNumber"), "block number")
        # Block time from the info (never raw_data.timestamp, which is set by
        # the sender). TRON uses milliseconds; integer division keeps it exact.
        block_timestamp = _parse_int(info.get("blockTimeStamp"), "block timestamp") // 1000

        return NormalizedTransaction(
            network=self.network,
            tx_hash=tx_hash,
            status=self._execution_status(solid_tx, info, contract_type),
            from_address=from_address,
            to_address=to_address,
            native_value_atomic=native_value,
            native_unit=NativeUnit.SUN,
            block_number=block_number,
            block_timestamp=block_timestamp,
        ), info

    def _post(self, path: str, tx_hash: str) -> dict[str, Any]:
        response = self._transport.post_json(
            self._base_url + path,
            {"value": tx_hash, "visible": False},
            self._timeout,
            headers=self._headers,
        )
        response = _require_object(response, "TRON response")
        if "Error" in response or "error" in response:
            raise TronApiError(f"TRON node returned an error for {path}")
        return response

    @staticmethod
    def _check_tx_id(tx: dict[str, Any], tx_hash: str) -> None:
        if _parse_tx_id(tx.get("txID"), "transaction id") != tx_hash:
            raise MalformedResponseError("TRON returned a different transaction")

    @staticmethod
    def _contract(tx: dict[str, Any]) -> dict[str, Any]:
        raw_data = _require_object(tx.get("raw_data"), "transaction raw_data")
        contracts = raw_data.get("contract")
        if not isinstance(contracts, list) or len(contracts) != 1:
            raise MalformedResponseError("TRON transaction must have exactly one contract")
        return _require_object(contracts[0], "transaction contract")

    def _contract_type(self, tx: dict[str, Any]) -> str:
        contract = self._contract(tx)
        contract_type = contract.get("type")
        if not isinstance(contract_type, str):
            raise MalformedResponseError("missing contract type in TRON response")
        if contract_type not in (TRANSFER_CONTRACT, TRIGGER_SMART_CONTRACT):
            raise UnsupportedTransactionError(
                f"TRON contract type {contract_type[:64]!r} is not supported"
            )
        return contract_type

    def _parse_contract(self, tx: dict[str, Any]) -> tuple[str, str, str, int]:
        """Return (contract type, sender, recipient, native value in sun)."""
        contract_type = self._contract_type(tx)
        parameter = _require_object(self._contract(tx).get("parameter"), "contract parameter")
        type_url = parameter.get("type_url")
        if type_url is not None and type_url != _TYPE_URL_PREFIX + contract_type:
            raise MalformedResponseError("contract type_url does not match its type")
        value = _require_object(parameter.get("value"), "contract value")
        sender = hex_to_base58_address(value.get("owner_address"), "owner address")

        if contract_type == TRANSFER_CONTRACT:
            # Native TRX transfer: amount is in sun.
            recipient = hex_to_base58_address(value.get("to_address"), "recipient")
            return contract_type, sender, recipient, _parse_int(value.get("amount"), "amount")

        # TriggerSmartContract: the recipient is the called contract. Only
        # call_value is native TRX (sun); the call data (e.g. a USDT transfer)
        # is not decoded and never reported as a native amount. Proto3 JSON
        # omits zero values, so a missing call_value means 0 sun.
        recipient = hex_to_base58_address(value.get("contract_address"), "contract address")
        call_value = value.get("call_value", 0)
        return contract_type, sender, recipient, _parse_int(call_value, "call value")

    @staticmethod
    def _execution_status(
        tx: dict[str, Any], info: dict[str, Any], contract_type: str
    ) -> TransactionStatus:
        ret = tx.get("ret")
        contract_ret = None
        if isinstance(ret, list) and len(ret) == 1 and isinstance(ret[0], dict):
            contract_ret = ret[0].get("contractRet")

        # TransactionInfo.result: SUCESS (sic, proto default, usually omitted)
        # or FAILED.
        info_result = info.get("result", "SUCESS")
        if info_result not in ("SUCESS", "FAILED"):
            raise MalformedResponseError("invalid execution result in TRON response")
        info_failed = info_result == "FAILED"

        receipt = info.get("receipt", {})
        if not isinstance(receipt, dict):
            raise MalformedResponseError("invalid receipt in TRON response")
        receipt_result = receipt.get("result")
        if receipt_result is not None and receipt_result != contract_ret:
            raise MalformedResponseError("receipt result does not match the transaction")

        if contract_ret == "SUCCESS":
            if info_failed:
                raise MalformedResponseError("TRON reports both success and failure")
            if contract_type == TRIGGER_SMART_CONTRACT and receipt_result is None:
                raise ExecutionResultUnknownError(
                    "smart contract execution result is not established"
                )
            return TransactionStatus.SUCCESS
        if contract_ret in _FAILED_CONTRACT_RESULTS:
            if not info_failed:
                raise MalformedResponseError("TRON reports both success and failure")
            return TransactionStatus.REVERTED
        # Missing, DEFAULT, UNKNOWN or unrecognised: do not guess.
        raise ExecutionResultUnknownError("TRON execution result is not established")
