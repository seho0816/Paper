def get_user_role(
    user_id: str,
) -> str:
    user = find_user_by_id(
        user_id
    )

    # CWE-476: Null 및 키 존재 여부를 안전하게 확인
    if not user or "role" not in user or not user["role"]:
        return ""

    return user[
        "role"
    ].upper()