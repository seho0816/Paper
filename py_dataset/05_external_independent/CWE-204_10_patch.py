import bcrypt

def resolve_login(
    _root,
    _info,
    email: str,
    password: str,
) -> dict:
    account = find_account(
        email
    )

    if account is None:
        # CWE-204: Observable Behavioral Difference.
        # To prevent an attacker from enumerating valid email addresses
        # by observing different error codes or response timings,
        # we simulate a password verification for non-existent accounts.
        # This makes the "user not found" scenario indistinguishable
        # from the "bad password" scenario both in error message and timing.
        dummy_password_hash = bcrypt.hashpw(
            b"this_is_a_long_random_string_to_simulate_a_password_hash_for_non_existent_users_xyz123",
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')

        # Perform a dummy password verification. The actual result is ignored,
        # but this ensures a similar processing delay to a real password check.
        verify_password(password, dummy_password_hash)

        # Return the same error code as a failed password attempt.
        return {
            "ok": False,
            "error_code": "BAD_PASSWORD",
        }

    if not verify_password(
        password,
        account["password_hash"],
    ):
        return {
            "ok": False,
            "error_code": "BAD_PASSWORD",
        }

    return {
        "ok": True,
    }
