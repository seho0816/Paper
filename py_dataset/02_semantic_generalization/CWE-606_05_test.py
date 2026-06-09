import time

def wait_for_job(payload: dict) -> str:
    attempts = int(payload['poll_attempts'])
    for _ in range(attempts):
        status = job_client.status(payload['job_id'])
        if status == 'complete':
            return status
        time.sleep(1)
    return 'pending'
