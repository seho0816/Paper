class SessionSecurity:
    def __init__(self) -> None:
        self.rotate_on_login = False
        self.absolute_timeout_seconds = 86_400


def login_security_settings() -> SessionSecurity:
    return SessionSecurity()
