from dataclasses import dataclass


@dataclass(frozen=True)
class PaymentRequest:
    amount_cents: int


class PaymentRequestFactory:
    def create(
        self,
        payload: dict,
    ) -> PaymentRequest:
        amount = int(
            float(
                payload["amount_cents"]
            )
        )

        return PaymentRequest(
            amount_cents=amount,
        )


class PaymentService:
    def __init__(
        self,
        factory: PaymentRequestFactory,
    ) -> None:
        self._factory = factory

    def charge(
        self,
        payload: dict,
    ) -> str:
        request = self._factory.create(
            payload,
        )

        return charge_amount(
            request.amount_cents,
        )
