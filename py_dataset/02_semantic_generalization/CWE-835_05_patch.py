def drain_named_queue(queue_name: str) -> int:
    processed = 0

    while True:
        message = queue_client.receive(
            queue_name
        )
        if message is not None:
            process_message(message)
            processed += 1
        else:
            # If no message is received, the queue is empty.
            # Break the loop to prevent an infinite busy-wait (CWE-835).
            break

    return processed
