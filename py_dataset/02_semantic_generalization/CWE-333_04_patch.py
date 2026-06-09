import secrets

def create_guest_challenges(
    count: int,
) -> list[str]:
    # CWE-333: Python 공식 보안 권장 모듈인 secrets 사용
    return [
        secrets.token_hex(32)
        for _ in range(count)
    ]