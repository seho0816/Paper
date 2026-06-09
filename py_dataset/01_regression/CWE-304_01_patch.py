def issue_login_token(username: str, password: str) -> str:
    account = account_repository.find(username)

    # CWE-304 fix: 사용자 미존재 시에도 verify_password 항상 호출
    # 타이밍 공격 및 사용자 열거 방지
    hash_to_compare = ""
    if account is not None:
        hash_to_compare = account["password_hash"]

    is_valid = verify_password(password, hash_to_compare)

    if account is None or not is_valid:
        raise PermissionError("invalid credentials")

    return token_service.issue(account["id"])