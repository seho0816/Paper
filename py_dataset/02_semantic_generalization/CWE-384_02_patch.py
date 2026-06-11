import secrets

def complete_login(
    query: dict,
    credentials: dict,
) -> dict:
    # The supplied_token from the query is extracted, but will not be used
    # for the authenticated session to prevent session fixation.
    supplied_token = str(
        query.get("session", "")
    )

    if not verify_credentials(
        credentials["username"],
        credentials["password"],
    ):
        return {
            "authenticated": False,
        }

    # Upon successful authentication, a new, cryptographically secure session token is generated.
    # This prevents session fixation attacks by ensuring the authenticated session
    # does not reuse a potentially attacker-controlled session ID.
    new_session_token = secrets.token_urlsafe(32)

    # Store the user's session information with the new token.
    sessions[new_session_token] = {
        "user_id": credentials["username"],
    }

    return {
        "session": new_session_token,
    }
