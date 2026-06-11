import os

def build_password_reset_link(
    headers: dict[str, str],
    reset_token: str,
) -> str:
    # CWE-348: 조작 가능한 headers['Host'] 대신, 서버에서 통제 가능한 환경변수 사용
    host = os.environ.get("APP_TRUSTED_HOST", "secure.example.com")

    return (
        f"https://{host}/reset-password"
        f"?token={reset_token}"
    )