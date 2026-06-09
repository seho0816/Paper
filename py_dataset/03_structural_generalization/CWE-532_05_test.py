import logging
from dataclasses import dataclass


@dataclass(frozen=True)
class PaymentRequest:
    account_id: str
    card_number: str
    cvv: str
    amount: int


class PaymentAudit:
    def __init__(self) -> None:
        self._logger = logging.getLogger(
            "payment-audit"
        )

    def record(
        self,
        request: PaymentRequest,
    ) -> None:
        self._logger.info(
            "payment account=%s card=%s cvv=%s amount=%s",
            request.account_id,
            request.card_number,
            request.cvv,
            request.amount,
        )


class PaymentService:
    def __init__(
        self,
        audit: PaymentAudit,
    ) -> None:
        self._audit = audit

    def charge(
        self,
        request: PaymentRequest,
    ) -> str:
        self._audit.record(request)
        return payment_gateway_charge(
            request,
        )
