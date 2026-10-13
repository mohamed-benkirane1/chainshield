"""Unified inspection of a transaction and its official USDT transfers.

A single call, ``TransactionAnalysisService.inspect_transaction``, returns
the provider's ``NormalizedTransaction`` and, when the transaction has a
final execution outcome, the official USDT ``Transfer`` events it recorded.

Reads are not atomic: the providers expose no snapshot, so the transaction is
read, then its transfers, then the transaction again. Any difference between
the two transaction reads, or any mismatch between the transaction and the
transfers, raises ``InconsistentAnalysisError`` instead of returning a result
that might mix two chain states. A change that happens and reverts entirely
between the two reads cannot be detected.

"Final" means what the provider reports: TRON ``success``/``reverted`` are
solidified; Ethereum ``success``/``reverted`` are mined with a receipt, which
is not a consensus finality guarantee.
"""

from collections.abc import Iterable
from typing import Protocol

from pydantic import BaseModel, ConfigDict, model_validator

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.token_transfer import NormalizedTokenTransfer
from app.providers.base import (
    BlockchainProvider,
    NormalizedTransaction,
    ProviderConfigurationError,
    ProviderError,
    TransactionNotFoundError,
    TransactionPendingError,
    TransactionStatus,
    TransactionUnconfirmedError,
)

FINAL_STATUSES = frozenset({TransactionStatus.SUCCESS, TransactionStatus.REVERTED})


class UsdtTransferProvider(BlockchainProvider, Protocol):
    """A chain provider that can also list official USDT transfers."""

    def get_usdt_transfers(self, tx_hash: str) -> list[NormalizedTokenTransfer]: ...


class InconsistentAnalysisError(ProviderError):
    """Successive reads disagree, so no reliable result can be reported."""


class TransactionInspection(BaseModel):
    """A transaction and its official USDT transfers.

    ``usdt_transfers`` is ``()`` when the transaction has a final outcome and
    recorded no official USDT ``Transfer`` (always the case when reverted),
    and ``None`` when that information is not available because the
    transaction is pending, unconfirmed or not found.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: Network
    tx_hash: str
    transaction: NormalizedTransaction
    usdt_transfers: tuple[NormalizedTokenTransfer, ...] | None

    @model_validator(mode="after")
    def _check_consistency(self) -> "TransactionInspection":
        if (self.transaction.network, self.transaction.tx_hash) != (
            self.network,
            self.tx_hash,
        ):
            raise ValueError("transaction does not match the inspected network and hash")
        if (self.usdt_transfers is None) != (self.transaction.status not in FINAL_STATUSES):
            raise ValueError("usdt_transfers is known only for a final transaction")
        if self.usdt_transfers is not None:
            if self.transaction.status is TransactionStatus.REVERTED and self.usdt_transfers:
                raise ValueError("a reverted transaction has no executed transfers")
            for transfer in self.usdt_transfers:
                if (transfer.network, transfer.tx_hash) != (self.network, self.tx_hash):
                    raise ValueError("transfer does not match the inspected transaction")
        return self


class TransactionAnalysisService:
    def __init__(self, providers: Iterable[UsdtTransferProvider]) -> None:
        self._providers: dict[Network, UsdtTransferProvider] = {}
        for provider in providers:
            if provider.network in self._providers:
                raise ProviderConfigurationError(
                    f"several providers configured for {provider.network.value}"
                )
            self._providers[provider.network] = provider

    def inspect_transaction(self, network: Network | str, tx_hash: str) -> TransactionInspection:
        """Inspect a transaction and its official USDT transfers.

        Raises ``ValueError`` for an unsupported network or a malformed hash,
        ``ProviderConfigurationError`` when no provider serves the network,
        ``InconsistentAnalysisError`` when successive reads disagree, and the
        provider's own errors unchanged.
        """
        network = Network(network)
        tx_hash = normalize_transaction_hash(network, tx_hash)
        provider = self._providers.get(network)
        if provider is None:
            raise ProviderConfigurationError(f"no provider configured for {network.value}")

        transaction = self._read_transaction(provider, network, tx_hash)
        if transaction.status not in FINAL_STATUSES:
            return TransactionInspection(
                network=network, tx_hash=tx_hash, transaction=transaction, usdt_transfers=None
            )

        try:
            transfers = tuple(provider.get_usdt_transfers(tx_hash))
        except (
            TransactionNotFoundError,
            TransactionPendingError,
            TransactionUnconfirmedError,
        ) as exc:
            raise InconsistentAnalysisError(
                "transaction is no longer final; it changed during the analysis"
            ) from exc
        for transfer in transfers:
            if (transfer.network, transfer.tx_hash) != (network, tx_hash):
                raise InconsistentAnalysisError("transfer does not match the transaction")
        if transaction.status is TransactionStatus.REVERTED and transfers:
            raise InconsistentAnalysisError("reverted transaction returned transfers")

        if self._read_transaction(provider, network, tx_hash) != transaction:
            raise InconsistentAnalysisError("transaction changed during the analysis")
        return TransactionInspection(
            network=network, tx_hash=tx_hash, transaction=transaction, usdt_transfers=transfers
        )

    @staticmethod
    def _read_transaction(
        provider: UsdtTransferProvider, network: Network, tx_hash: str
    ) -> NormalizedTransaction:
        transaction = provider.get_transaction(tx_hash)
        if (transaction.network, transaction.tx_hash) != (network, tx_hash):
            raise InconsistentAnalysisError("provider returned another transaction")
        return transaction
