_TIMING_GUARD_HASH = "$2b$12$L7CjV6P9sB3tZ1D2xR7Jj.Q9.Q9.Q9.Q9.Q9.Q9.Q9.Q9.Q9.Q9."


def authenticate(email: str, password: str) -> bool:
    account = find_user_by_email(email)

    # CWE-208 fix: 항상 verify_password 호출하여 타이밍 공격 방지
    # 사용자 존재 여부와 관계없이 동일한 처리 시간 보장
    hash_to_verify = _TIMING_GUARD_HASH
    if account is not None:
        hash_to_verify = account["password_hash"]

    return verify_password(password, hash_to_verify)