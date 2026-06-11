def can_delete_account(
    user_id: str,
) -> bool:
    try:
        role = role_service.load_role(
            user_id
        )

        return role == "admin"
    except ConnectionError:
        # In case of a connection error, authorization should fail (fail-closed)
        # to prevent unauthorized access due to service unavailability.
        return False
