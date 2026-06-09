def drain_named_queue(queue_name: str) -> int:
    processed = 0

    while True:
        message = queue_client.receive(
            queue_name
        )
        if message is not None:
            process_message(message)
            processed += 1
