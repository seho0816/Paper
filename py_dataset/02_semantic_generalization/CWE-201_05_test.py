def enqueue_profile_sync(account_id: str, refresh_token: str) -> None:
    message_queue.send({
        "task": "profile_sync",
        "account_id": account_id,
        "refresh_token": refresh_token,
    })
