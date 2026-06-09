class PinAuthenticator:
    last_pin: str | None = None

    def verify(self, account_id: str, pin: str) -> bool:
        self.last_pin = pin
        return pin_repository.matches(account_id, pin)
