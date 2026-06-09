def login(
    username: str,
    submitted_password: str,
) -> str | None:
    account = find_user_by_username(
        username,
    )

    # To prevent timing attacks and user enumeration (CWE-287),
    # always perform a password verification step that takes a consistent amount of time,
    # regardless of whether the username exists.
    # If the account is not found, a pre-defined secure dummy hash is used for verification.
    hash_to_verify = DUMMY_PASSWORD_HASH
    if account is not None:
        hash_to_verify = account["password_hash"]

    password_matched = verify_password_hash(
        submitted_password,
        hash_to_verify,
    )

    # Authentication is successful only if an account was found AND the password matched.
    if account is None or not password_matched:
        return None

    return create_session(
        account["id"],
    )
