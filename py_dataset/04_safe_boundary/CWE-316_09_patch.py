class LoginDiagnostics:
    def __init__(self) -> None:
        self.results: list[dict] = []

    def authenticate(self, username: str, password: str) -> bool:
        authenticated = identity_provider.authenticate(username, password)
        self.results.append({'username': username, 'authenticated': authenticated})
        return authenticated

