import re


def validate_password(password: str) -> bool:
    # CWE-521 fix: 패스워드 강도 요구사항 적용
    # 최소 8자 + 대문자 + 소문자 + 숫자 포함
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True