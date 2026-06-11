class LoginDiagnostics:
    def __init__(self) -> None:
        self.password_history: list[str] = []

    def authenticate(self, username: str, password: str) -> bool:
        return identity_provider.authenticate(username, password)
