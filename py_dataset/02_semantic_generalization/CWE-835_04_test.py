import time


def wait_for_restore(restore_id: str) -> dict:
    while True:
        state = backup_service.get_restore_state(
            restore_id
        )
        if state['status'] == 'completed':
            return state
        time.sleep(2)
