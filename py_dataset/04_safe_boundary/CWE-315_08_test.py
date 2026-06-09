import secrets


def create_session_cookie(
    account_id: str,
) -> dict:
    session_id = secrets.token_urlsafe(
        32
    )
    session_store.save(
        session_id,
        {
            "account_id": account_id,
        },
    )

    return {
        "name": "session",
        "value": session_id,
        "http_only": True,
        "secure": True,
        "same_site": "Lax",
    }
