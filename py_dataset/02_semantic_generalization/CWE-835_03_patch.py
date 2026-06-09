import time


def await_device_ready(device_id: str) -> dict:
    MAX_WAIT_SECONDS = 300  # Maximum time to wait for the device to become ready (e.g., 5 minutes)
    start_time = time.time()

    while True:
        state = device_api.get_state(device_id)
        if state['phase'] == 'ready':
            return state
        
        # Check for timeout before the next sleep cycle
        if time.time() - start_time > MAX_WAIT_SECONDS:
            raise TimeoutError(f"Device {device_id} did not become ready within {MAX_WAIT_SECONDS} seconds.")
            
        time.sleep(1)
