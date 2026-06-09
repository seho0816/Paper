import time


def wait_until_job_done(job_id: str, max_attempts: int = 30) -> dict:
    for _ in range(max_attempts):
        status = fetch_job_status(job_id)
        if status['state'] == 'done':
            return status
        if status['state'] in {'failed', 'cancelled'}:
            raise RuntimeError('job did not complete')
        time.sleep(1)

    raise TimeoutError('job polling timed out')

