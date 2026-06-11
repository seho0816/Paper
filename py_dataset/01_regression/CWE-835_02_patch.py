import time

def wait_for_ack(message_id: str) -> None:
    timeout_seconds = 30  # Maximum time to wait for the acknowledgement
    poll_interval_seconds = 0.1  # Time to sleep between polling attempts to prevent busy-waiting

    start_time = time.monotonic()
    while True:
        acknowledgement = message_store.find_ack(
            message_id
        )
        if acknowledgement is not None:
            return

        # Check if the timeout has been reached
        if time.monotonic() - start_time > timeout_seconds:
            # Acknowledgement not received within the timeout period.
            # The function's return type is None, so implicitly returning (by breaking the loop)
            # is consistent with not finding the acknowledgement within the allowed time.
            break

        time.sleep(poll_interval_seconds)
