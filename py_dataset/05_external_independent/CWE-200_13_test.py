def resolve_user(
    _root,
    _info,
    user_id: str,
) -> dict:
    user = load_user(
        user_id,
    )

    return {
        "id": user["id"],
        "email": user["email"],
        "password_hash": user["password_hash"],
        "recovery_answer": user["recovery_answer"],
    }
