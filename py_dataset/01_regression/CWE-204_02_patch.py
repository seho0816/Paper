def register_account(
    email: str,
    password: str,
) -> tuple[dict, int]:
    if find_user_by_email(
        email
    ) is not None:
        # CWE-204 mitigation: Return a generic success message
        # even if the email is already registered, to prevent
        # enumeration of existing accounts. The 'create_account'
        # function is not called in this case, preventing actual
        # account creation or potential errors.
        return {
            "created": True,
        }, 201

    create_account(
        email,
        password,
    )

    return {
        "created": True,
    }, 201
