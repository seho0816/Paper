def login(
    current_session_id: str,
    username: str,
    password: str,
) -> str | None:
    account = verify_account(
        username,
        password,
    )

    if account is None:
        return None

    # CWE-384 (Session Fixation) Fix:
    # A session fixation vulnerability occurs if an attacker can force a user's
    # session ID to a known value, and then impersonate the user after they log in.
    # The 'rotate_session_id' function is designed to prevent this by invalidating
    # the old session and generating a new, unpredictable session ID.
    # To ensure the new session ID is not influenced by a potentially attacker-controlled
    # 'current_session_id' and forces a fresh, cryptographically secure ID generation,
    # an empty string is passed. This assumes 'rotate_session_id' handles:
    # 1. Invalidating the previous session (e.g., from the global session context or cookie).
    # 2. Generating a truly new and random session ID when an empty string is provided,
    #    to prevent any derivation from a potentially compromised or fixed ID.
    new_session_id = rotate_session_id("")
    bind_session_to_account(
        new_session_id,
        account["id"],
    )

    return new_session_id
