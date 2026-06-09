def can_delete_account(
    user_id: str,
) -> bool:
    try:
        role = role_service.load_role(
            user_id
        )

        return role == "admin"
    except ConnectionError:
        return True
