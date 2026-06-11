import time


def wait_for_restore(restore_id: str) -> dict:
    MAX_WAIT_SECONDS = 300  # Maximum time to wait (e.g., 5 minutes)
    POLL_INTERVAL_SECONDS = 2 # The original sleep duration

    start_time = time.monotonic()

    while True:
        if (time.monotonic() - start_time) > MAX_WAIT_SECONDS:
            # If the maximum wait time is exceeded, exit the loop and return a timeout status.
            return {'status': 'timeout', 'restore_id': restore_id, 'message': 'Restore operation timed out.'}

        state = backup_service.get_restore_state(
            restore_id
        )
        if state['status'] == 'completed':
            return state
        time.sleep(POLL_INTERVAL_SECONDS)
