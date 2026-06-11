import hmac


def handle_oauth_callback(
    query: dict,
    session: dict,
) -> dict:
    # Retrieve the state from the query. It might be missing or empty.
    submitted_state = query.get("state")

    # Retrieve the expected state from the session. Using None as default
    # clearly indicates if the state was truly missing from the session.
    expected_state = session.pop("oauth_state", None)

    # CWE-352: Cross-Site Request Forgery (CSRF)
    # The original code's use of `str(query.get("state", ""))` and
    # `str(session.pop("oauth_state", ""))` would allow `hmac.compare_digest("", "")`
    # to return True if both states were missing/empty. This bypasses the CSRF protection.
    # A robust CSRF protection requires both states to be explicitly present and non-empty strings.

    # 1. Validate the submitted state. It must be a non-empty string.
    if not isinstance(submitted_state, str) or not submitted_state:
        raise PermissionError("Submitted OAuth 'state' parameter is missing or empty.")

    # 2. Validate the expected state. It must have been present in the session
    #    as a non-empty string.
    if not isinstance(expected_state, str) or not expected_state:
        raise PermissionError("Expected OAuth 'state' not found or invalid in session.")

    # 3. Perform the secure comparison using hmac.compare_digest.
    if not hmac.compare_digest(
        submitted_state,
        expected_state,
    ):
        raise PermissionError(
            "Invalid OAuth state: state mismatch."
        )

    # If all state validation checks pass, proceed to exchange the code for a token.
    # The original code relies on 'code' being present in the query, we maintain this.
    return exchange_code_for_token(
        str(query["code"]),
    )
