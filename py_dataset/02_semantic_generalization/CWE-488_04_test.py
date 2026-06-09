class PaymentResolver:
    def __init__(self) -> None:
        self._last_payment: dict | None = None

    async def resolve(self, account_id: str, payment_id: str) -> dict:
        payment = await payment_repository.find(account_id, payment_id)
        if payment is None:
            return self._last_payment or {'error': 'not found'}
        self._last_payment = payment
        return payment
