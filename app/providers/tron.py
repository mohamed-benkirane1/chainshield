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

from app.domain.analysis_input import (
    Network,
    normalize_transaction_hash,
    validate_tron_address,
)
from app.providers.base import (
    ExecutionResultUnknownError,
    MalformedResponseError,
    NativeUnit,
    NormalizedTransaction,
    ProviderConfigurationError,
    ProviderError,
    ReceiptUnavailableError,
    TransactionStatus,
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
        tx_hash = normalize_transaction_hash(Network.TRON, tx_hash)

        tx = self._post(GET_TRANSACTION_PATH, tx_hash)
        if not tx:
            return NormalizedTransaction(
                network=self.network, tx_hash=tx_hash, status=TransactionStatus.NOT_FOUND
            )
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
            )
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
        )

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
