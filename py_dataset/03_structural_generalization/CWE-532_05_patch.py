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
        # CWE-532: Inclusion of Sensitive Information in Log Files
        # Mask sensitive card_number and cvv before logging to prevent data exposure.
        # For card_number, show only the last 4 digits and mask the rest.
        # For CVV, fully mask it as it should never be logged, even partially.
        masked_card_number = "************" + request.card_number[-4:]
        masked_cvv = "***"

        self._logger.info(
            "payment account=%s card=%s cvv=%s amount=%s",
            request.account_id,
            masked_card_number,
            masked_cvv,
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
        # Assumed external function, not part of the scope for this fix.
        return payment_gateway_charge(
            request,
        )
