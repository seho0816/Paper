import time


def await_device_ready(device_id: str) -> dict:
    while True:
        state = device_api.get_state(device_id)
        if state['phase'] == 'ready':
            return state
        time.sleep(1)
