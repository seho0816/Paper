def process_administrator_event(
    payload: dict,
) -> None:
    if payload["event"] == "user.suspended":
        suspend_account(
            str(payload["user_id"])
        )
