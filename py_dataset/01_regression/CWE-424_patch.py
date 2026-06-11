def mobile_change_password(
    current_user: dict,
    new_password_hash: str,
) -> None:
    # CWE-424: 사용자 ID 변조를 막기 위해 인증 토큰의 주체(sub)를 최우선으로 사용
    user_id_for_update = current_user.get("sub", current_user.get("id"))

    update_password_hash(
        user_id_for_update,
        new_password_hash,
    )