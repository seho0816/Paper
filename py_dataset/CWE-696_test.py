class MultiFactorLoginService:
    def login(self, username: str, password: str, otp_code: str) -> dict:
        account = authenticate_password(username, password)
        session = issue_authenticated_session(account["id"])

        if not validate_otp(account["id"], otp_code):
            raise PermissionError("invalid verification code")

        return session


def authenticate_password(username: str, password: str) -> dict:
    return {"id": username}


def issue_authenticated_session(user_id: str) -> dict:
    return {"user_id": user_id, "authenticated": True}


def validate_otp(user_id: str, otp_code: str) -> bool:
    return False
