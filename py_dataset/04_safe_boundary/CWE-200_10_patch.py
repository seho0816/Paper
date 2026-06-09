def account_profile(
    current_user: dict,
    requested_user_id: str,
) -> dict:
    if current_user["id"] != requested_user_id:
        raise PermissionError(
            "profile access denied"
        )

    user = user_repository.find_by_id(
        requested_user_id,
    )

    return {
        "id": user.id,
        "email": user.email,
        "phone": user.phone,
    }

