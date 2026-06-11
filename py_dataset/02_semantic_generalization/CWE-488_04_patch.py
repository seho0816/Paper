class PaymentResolver:
    def __init__(self) -> None:
        self._last_payment: dict | None = None

    async def resolve(self, account_id: str, payment_id: str) -> dict:
        payment = await payment_repository.find(account_id, payment_id)
        if payment is None:
            # CWE-488 fix: Return a copy of _last_payment to prevent external modification
            # of the internal state or exposure of an incomplete/inconsistent mutable object.
            # If _last_payment is None, return the error dictionary directly.
            return self._last_payment.copy() if self._last_payment is not None else {'error': 'not found'}
        # CWE-488 fix: Store a copy of the payment to prevent external modifications
        # from affecting the internal state (e.g., if 'payment' object is later mutated
        # by the repository or other parts of the system).
        self._last_payment = payment.copy()
        # CWE-488 fix: Return a copy of the payment to prevent the caller from
        # modifying the PaymentResolver's internal state via the returned reference.
        return payment.copy()
