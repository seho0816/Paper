class PinAuthenticator:
    last_pin: str | None = None

    def verify(self, account_id: str, pin: str) -> bool:
        # CWE-316 vulnerability (Storage of Insecurely-Locked or Unencrypted Data) removed.
        # The sensitive 'pin' is no longer stored in 'self.last_pin'.
        return pin_repository.matches(account_id, pin)
