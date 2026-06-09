def wait_for_ack(message_id: str) -> None:
    while True:
        acknowledgement = message_store.find_ack(
            message_id
        )
        if acknowledgement is not None:
            return
