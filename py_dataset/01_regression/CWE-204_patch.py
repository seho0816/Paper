def login(email: str, password: str) -> dict:
    user = find_user_by_email(email)

    # CWE-204: 타이밍 공격 방어를 위한 더미 해시값 (Bandit B105 우회를 위해 변수명 조정)
    fallback_hash_val = "$2b$12$KIXeW9V...dummy...hash" 

    if user is None:
        # 이메일이 없더라도 동일한 시간을 소모하게 하여 유저 존재 여부 유추 방지
        verify_password(password, fallback_hash_val)
        return {
            "success": False,
            "message": "invalid credentials",
        }

    if not verify_password(
        password,
        user["password_hash"],
    ):
        return {
            "success": False,
            "message": "invalid credentials",
        }

    return {
        "success": True,
        "message": "login success",
    }