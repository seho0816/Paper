import shelve


def persist_session(
    session_id: str,
    access_token: str,
    refresh_token: str,
) -> None:
    with shelve.open(
        "sessions.db",
    ) as store:
        store[session_id] = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
