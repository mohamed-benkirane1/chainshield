import json
import socket
from typing import Any

import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.features.transaction_features import TransactionFeatures, extract_transaction_features
from app.providers.base import NativeUnit, NormalizedTransaction, TransactionStatus
from app.services.transaction_analysis import TransactionInspection

ETH_HASH = "0x" + "ab" * 32
TRON_HASH = "cd" * 32

ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
DAVE = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"

TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_ALICE = base58.b58encode_check(b"\x41" + bytes(range(1, 21))).decode()
TRON_BOB = base58.b58encode_check(b"\x41" + bytes(range(21, 41))).decode()

MEASURES = (
    "usdt_transfer_count",
    "has_usdt_transfers",
    "unique_usdt_senders",
    "unique_usdt_recipients",
    "unique_usdt_participants",
    "self_transfer_count",
    "zero_amount_transfer_count",
    "gross_usdt_event_amount_atomic",
    "max_usdt_transfer_amount_atomic",
)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


# --- Builders (real project models with valid data) ---------------------------


def eth_tx(status: TransactionStatus = TransactionStatus.SUCCESS) -> NormalizedTransaction:
    fields: dict[str, Any] = {"network": Network.ETHEREUM, "tx_hash": ETH_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(
            from_address=ALICE, to_address=ETH_USDT,
            native_value_atomic=0, native_unit=NativeUnit.WEI,
        )
    if status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED):
        fields.update(block_number=19_000_000, block_timestamp=1_705_000_000)
    return NormalizedTransaction(**fields)


def tron_tx(status: TransactionStatus = TransactionStatus.SUCCESS) -> NormalizedTransaction:
    fields: dict[str, Any] = {"network": Network.TRON, "tx_hash": TRON_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(
            from_address=TRON_ALICE, to_address=TRON_USDT,
            native_value_atomic=0, native_unit=NativeUnit.SUN,
        )
    if status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED):
        fields.update(block_number=60_000_000, block_timestamp=1_705_000_002)
    return NormalizedTransaction(**fields)


def transfer(sender: str, recipient: str, amount: int, log_index: int = 0):
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM,
        tx_hash=ETH_HASH,
        token_symbol="USDT",
        token_contract=ETH_USDT,
        from_address=sender,
        to_address=recipient,
        amount_atomic=amount,
        decimals=6,
        log_index=log_index,
    )


def tron_transfer(amount: int = 10_000_000_000) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.TRON,
        tx_hash=TRON_HASH,
        token_symbol="USDT",
        token_contract=TRON_USDT,
        from_address=TRON_ALICE,
        to_address=TRON_BOB,
        amount_atomic=amount,
        decimals=6,
    )


def inspect(transaction: NormalizedTransaction, transfers: Any) -> TransactionInspection:
    return TransactionInspection(
        network=transaction.network,
        tx_hash=transaction.tx_hash,
        transaction=transaction,
        usdt_transfers=None if transfers is None else tuple(transfers),
    )


def eth_features(*transfers: NormalizedTokenTransfer) -> TransactionFeatures:
    events = [
        transfer(t.from_address, t.to_address, t.amount_atomic, index)
        for index, t in enumerate(transfers)
    ]
    return extract_transaction_features(inspect(eth_tx(), events))


def measures(features: TransactionFeatures) -> dict[str, Any]:
    return {name: getattr(features, name) for name in MEASURES}


# --- 1-3: basic extraction ------------------------------------------------------


def test_ethereum_single_transfer() -> None:
    features = extract_transaction_features(inspect(eth_tx(), [transfer(ALICE, BOB, 35_000_000)]))

    assert features == TransactionFeatures(
        network=Network.ETHEREUM,
        tx_hash=ETH_HASH,
        transaction_status=TransactionStatus.SUCCESS,
        transfer_data_available=True,
        usdt_transfer_count=1,
        has_usdt_transfers=True,
        unique_usdt_senders=1,
        unique_usdt_recipients=1,
        unique_usdt_participants=2,
        self_transfer_count=0,
        zero_amount_transfer_count=0,
        gross_usdt_event_amount_atomic=35_000_000,
        max_usdt_transfer_amount_atomic=35_000_000,
    )


def test_tron_single_transfer() -> None:
    features = extract_transaction_features(inspect(tron_tx(), [tron_transfer()]))

    assert features.network is Network.TRON
    assert features.tx_hash == TRON_HASH
    assert measures(features) == {
        "usdt_transfer_count": 1,
        "has_usdt_transfers": True,
        "unique_usdt_senders": 1,
        "unique_usdt_recipients": 1,
        "unique_usdt_participants": 2,
        "self_transfer_count": 0,
        "zero_amount_transfer_count": 0,
        "gross_usdt_event_amount_atomic": 10_000_000_000,
        "max_usdt_transfer_amount_atomic": 10_000_000_000,
    }


def test_three_transfers_like_a_routed_swap() -> None:
    # Same shape as the real mainnet swap: 105 then 104.685 twice.
    features = eth_features(
        transfer(ALICE, DAVE, 105_000_000),
        transfer(DAVE, BOB, 104_685_000),
        transfer(BOB, CAROL, 104_685_000),
    )

    assert measures(features) == {
        "usdt_transfer_count": 3,
        "has_usdt_transfers": True,
        "unique_usdt_senders": 3,
        "unique_usdt_recipients": 3,
        "unique_usdt_participants": 4,
        "self_transfer_count": 0,
        "zero_amount_transfer_count": 0,
        # Gross event sum, not the swap's economic value (~105 USDT).
        "gross_usdt_event_amount_atomic": 314_370_000,
        "max_usdt_transfer_amount_atomic": 105_000_000,
    }


# --- 4-6, 21: participants ------------------------------------------------------


def test_repeated_transfers_between_the_same_addresses() -> None:
    features = eth_features(*(transfer(ALICE, BOB, 1_000_000) for _ in range(4)))

    assert features.usdt_transfer_count == 4
    assert features.unique_usdt_senders == 1
    assert features.unique_usdt_recipients == 1
    assert features.unique_usdt_participants == 2


def test_participants_shared_across_transfers_are_counted_once() -> None:
    features = eth_features(
        transfer(ALICE, BOB, 1),
        transfer(BOB, ALICE, 2),
        transfer(ALICE, CAROL, 3),
        transfer(CAROL, BOB, 4),
    )

    assert features.unique_usdt_senders == 3  # ALICE, BOB, CAROL
    assert features.unique_usdt_recipients == 3  # BOB, ALICE, CAROL
    assert features.unique_usdt_participants == 3  # union, no double count


def test_self_transfer() -> None:
    features = eth_features(transfer(ALICE, ALICE, 5_000_000), transfer(ALICE, BOB, 1))

    assert features.self_transfer_count == 1
    assert features.unique_usdt_senders == 1
    assert features.unique_usdt_recipients == 2
    assert features.unique_usdt_participants == 2


def test_only_self_transfers() -> None:
    features = eth_features(transfer(BOB, BOB, 1), transfer(BOB, BOB, 2))

    assert features.self_transfer_count == 2
    assert features.unique_usdt_participants == 1


# --- 7-11, 20: amounts -----------------------------------------------------------


def test_zero_amount_transfer() -> None:
    features = eth_features(transfer(ALICE, BOB, 0))

    assert features.zero_amount_transfer_count == 1
    assert features.gross_usdt_event_amount_atomic == 0
    assert features.max_usdt_transfer_amount_atomic == 0
    assert features.has_usdt_transfers is True


def test_several_zero_transfers_among_others() -> None:
    features = eth_features(
        transfer(ALICE, BOB, 0), transfer(BOB, CAROL, 7), transfer(CAROL, DAVE, 0)
    )

    assert features.zero_amount_transfer_count == 2
    assert features.gross_usdt_event_amount_atomic == 7
    assert features.max_usdt_transfer_amount_atomic == 7


def test_max_uint256_single_amount_is_exact() -> None:
    features = eth_features(transfer(ALICE, BOB, MAX_UINT256))

    assert type(features.gross_usdt_event_amount_atomic) is int
    assert features.gross_usdt_event_amount_atomic == 2**256 - 1
    assert features.max_usdt_transfer_amount_atomic == 2**256 - 1


def test_gross_sum_may_exceed_uint256_and_stays_exact() -> None:
    features = eth_features(
        transfer(ALICE, BOB, MAX_UINT256),
        transfer(BOB, CAROL, MAX_UINT256),
        transfer(CAROL, DAVE, 1),
    )

    assert features.gross_usdt_event_amount_atomic == 2 * MAX_UINT256 + 1
    assert features.gross_usdt_event_amount_atomic > MAX_UINT256
    assert features.max_usdt_transfer_amount_atomic == MAX_UINT256


def test_identical_amounts() -> None:
    features = eth_features(*(transfer(ALICE, BOB, 2**53 + 1) for _ in range(3)))

    assert features.gross_usdt_event_amount_atomic == 3 * (2**53 + 1)
    assert features.max_usdt_transfer_amount_atomic == 2**53 + 1


def test_maximum_with_several_amounts_in_any_order() -> None:
    features = eth_features(
        transfer(ALICE, BOB, 300), transfer(BOB, CAROL, 10**30), transfer(CAROL, DAVE, 5)
    )

    assert features.max_usdt_transfer_amount_atomic == 10**30
    assert features.gross_usdt_event_amount_atomic == 10**30 + 305


# --- 12-13, 19: final transactions without executed transfers -----------------------


def test_success_without_usdt_event() -> None:
    features = extract_transaction_features(inspect(eth_tx(), []))

    assert features.transfer_data_available is True
    assert features.transaction_status is TransactionStatus.SUCCESS
    assert measures(features) == {
        "usdt_transfer_count": 0,
        "has_usdt_transfers": False,
        "unique_usdt_senders": 0,
        "unique_usdt_recipients": 0,
        "unique_usdt_participants": 0,
        "self_transfer_count": 0,
        "zero_amount_transfer_count": 0,
        "gross_usdt_event_amount_atomic": 0,
        "max_usdt_transfer_amount_atomic": None,
    }


@pytest.mark.parametrize("transaction", [eth_tx(TransactionStatus.REVERTED),
                                         tron_tx(TransactionStatus.REVERTED)])
def test_reverted_transaction(transaction: NormalizedTransaction) -> None:
    features = extract_transaction_features(inspect(transaction, []))

    assert features.transaction_status is TransactionStatus.REVERTED
    assert features.transfer_data_available is True
    assert features.usdt_transfer_count == 0
    assert features.has_usdt_transfers is False
    assert features.gross_usdt_event_amount_atomic == 0
    assert features.max_usdt_transfer_amount_atomic is None


# --- 14-18: non-final transactions ----------------------------------------------------


@pytest.mark.parametrize(
    "transaction",
    [
        eth_tx(TransactionStatus.PENDING),
        tron_tx(TransactionStatus.UNCONFIRMED),
        eth_tx(TransactionStatus.NOT_FOUND),
        tron_tx(TransactionStatus.NOT_FOUND),
    ],
    ids=["ethereum-pending", "tron-unconfirmed", "ethereum-not-found", "tron-not-found"],
)
def test_non_final_transaction_has_only_unknown_measures(
    transaction: NormalizedTransaction,
) -> None:
    features = extract_transaction_features(inspect(transaction, None))

    assert features.transaction_status is transaction.status
    assert features.network is transaction.network
    assert features.transfer_data_available is False
    assert all(value is None for value in measures(features).values())


def test_unknown_is_none_not_zero() -> None:
    unknown = extract_transaction_features(inspect(eth_tx(TransactionStatus.PENDING), None))
    empty = extract_transaction_features(inspect(eth_tx(), []))

    assert unknown.usdt_transfer_count is None and empty.usdt_transfer_count == 0
    assert unknown.gross_usdt_event_amount_atomic is None
    assert empty.gross_usdt_event_amount_atomic == 0


def test_unknown_is_none_not_false() -> None:
    unknown = extract_transaction_features(inspect(tron_tx(TransactionStatus.UNCONFIRMED), None))
    empty = extract_transaction_features(inspect(tron_tx(), []))

    assert unknown.has_usdt_transfers is None
    assert empty.has_usdt_transfers is False


def test_every_status_is_preserved() -> None:
    cases = {
        TransactionStatus.SUCCESS: inspect(eth_tx(), []),
        TransactionStatus.REVERTED: inspect(eth_tx(TransactionStatus.REVERTED), []),
        TransactionStatus.PENDING: inspect(eth_tx(TransactionStatus.PENDING), None),
        TransactionStatus.UNCONFIRMED: inspect(tron_tx(TransactionStatus.UNCONFIRMED), None),
        TransactionStatus.NOT_FOUND: inspect(eth_tx(TransactionStatus.NOT_FOUND), None),
    }

    for status, inspection in cases.items():
        assert extract_transaction_features(inspection).transaction_status is status
    assert set(cases) == set(TransactionStatus)


# --- 22-24: determinism, immutability, no mutation ---------------------------------------


def test_extraction_is_exact_and_deterministic() -> None:
    inspection = inspect(
        eth_tx(),
        [transfer(ALICE, BOB, 7, 0), transfer(BOB, CAROL, 0, 1), transfer(CAROL, CAROL, 9, 2)],
    )

    results = [extract_transaction_features(inspection) for _ in range(5)]

    assert all(result == results[0] for result in results)
    assert results[0].model_dump_json() == results[-1].model_dump_json()
    assert measures(results[0]) == {
        "usdt_transfer_count": 3,
        "has_usdt_transfers": True,
        "unique_usdt_senders": 3,
        "unique_usdt_recipients": 2,
        "unique_usdt_participants": 3,
        "self_transfer_count": 1,
        "zero_amount_transfer_count": 1,
        "gross_usdt_event_amount_atomic": 16,
        "max_usdt_transfer_amount_atomic": 9,
    }


def test_features_are_immutable() -> None:
    features = eth_features(transfer(ALICE, BOB, 1))

    with pytest.raises(ValidationError):
        features.usdt_transfer_count = 5  # type: ignore[misc]


def test_extraction_does_not_mutate_the_inspection() -> None:
    inspection = inspect(eth_tx(), [transfer(ALICE, BOB, 1, 0), transfer(BOB, CAROL, 2, 1)])
    before = inspection.model_dump_json()

    extract_transaction_features(inspection)

    assert inspection.model_dump_json() == before


# --- 25: model consistency ----------------------------------------------------------------


def _valid(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "network": Network.ETHEREUM,
        "tx_hash": ETH_HASH,
        "transaction_status": TransactionStatus.SUCCESS,
        "transfer_data_available": True,
        "usdt_transfer_count": 2,
        "has_usdt_transfers": True,
        "unique_usdt_senders": 1,
        "unique_usdt_recipients": 2,
        "unique_usdt_participants": 2,
        "self_transfer_count": 1,
        "zero_amount_transfer_count": 0,
        "gross_usdt_event_amount_atomic": 10,
        "max_usdt_transfer_amount_atomic": 6,
    }
    fields.update(overrides)
    return fields


def test_valid_features_are_accepted() -> None:
    assert TransactionFeatures(**_valid()).usdt_transfer_count == 2


@pytest.mark.parametrize(
    "overrides",
    [
        {"extra": 1},
        {"network": "ethereum"},  # strict: enum instance required
        {"transaction_status": "success"},
        {"tx_hash": "ab" * 32},
        {"tx_hash": ETH_HASH.upper().replace("0X", "0x")},
        {"transfer_data_available": False},  # final status must have data
        {"usdt_transfer_count": None},
        {"usdt_transfer_count": 2.0},
        {"usdt_transfer_count": "2"},
        {"usdt_transfer_count": -1},
        {"has_usdt_transfers": 1},
        {"has_usdt_transfers": False},
        {"unique_usdt_senders": 0},
        {"unique_usdt_senders": 3},
        {"unique_usdt_recipients": 3},
        {"unique_usdt_participants": 1},  # below max(senders, recipients)
        {"unique_usdt_participants": 4},  # above senders + recipients
        {"self_transfer_count": 3},
        {"zero_amount_transfer_count": 3},
        {"gross_usdt_event_amount_atomic": 5},  # below the maximum
        {"gross_usdt_event_amount_atomic": 13},  # above count * maximum
        {"gross_usdt_event_amount_atomic": 10.0},
        {"max_usdt_transfer_amount_atomic": None},
        {"max_usdt_transfer_amount_atomic": MAX_UINT256 + 1},
        {"zero_amount_transfer_count": 2, "max_usdt_transfer_amount_atomic": 6},
    ],
)
def test_inconsistent_features_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        TransactionFeatures(**_valid(**overrides))


@pytest.mark.parametrize(
    "overrides",
    [
        {"transaction_status": TransactionStatus.REVERTED},  # reverted with transfers
        {"usdt_transfer_count": 0, "has_usdt_transfers": False},  # empty but nonzero measures
    ],
)
def test_inconsistent_empty_or_reverted_features_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        TransactionFeatures(**_valid(**overrides))


@pytest.mark.parametrize("status", [TransactionStatus.PENDING, TransactionStatus.NOT_FOUND])
@pytest.mark.parametrize("name", MEASURES)
def test_non_final_features_cannot_carry_any_measure(
    status: TransactionStatus, name: str
) -> None:
    value: Any = False if name == "has_usdt_transfers" else 0
    with pytest.raises(ValidationError, match="unavailable"):
        TransactionFeatures(
            network=Network.ETHEREUM,
            tx_hash=ETH_HASH,
            transaction_status=status,
            transfer_data_available=False,
            **{name: value},
        )


def test_non_final_status_cannot_claim_available_data() -> None:
    with pytest.raises(ValidationError):
        TransactionFeatures(
            network=Network.TRON,
            tx_hash=TRON_HASH,
            transaction_status=TransactionStatus.UNCONFIRMED,
            transfer_data_available=True,
        )


# --- 26: exact serialization ------------------------------------------------------------------


def test_large_integers_serialize_exactly() -> None:
    features = eth_features(transfer(ALICE, BOB, MAX_UINT256), transfer(BOB, CAROL, MAX_UINT256))

    dumped = features.model_dump_json()

    parsed = json.loads(dumped, parse_float=lambda _: pytest.fail("float found"))
    assert parsed["gross_usdt_event_amount_atomic"] == 2 * MAX_UINT256
    assert str(2 * MAX_UINT256) in dumped
    assert TransactionFeatures.model_validate_json(dumped) == features


def test_unknown_measures_serialize_as_null() -> None:
    features = extract_transaction_features(inspect(eth_tx(TransactionStatus.PENDING), None))

    parsed = json.loads(features.model_dump_json())

    assert all(parsed[name] is None for name in MEASURES)
    assert parsed["transfer_data_available"] is False


# --- 27: no network ------------------------------------------------------------------------


def test_extraction_needs_no_provider_or_network() -> None:
    # The socket guard is active: any I/O attempt would fail this test.
    features = eth_features(transfer(ALICE, BOB, 1))

    assert features.usdt_transfer_count == 1
