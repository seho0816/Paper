import os
import time

def wait_until_job_done(job_id: str) -> dict:
    try:
        timeout_seconds = int(os.environ.get("JOB_WAIT_TIMEOUT_SECONDS", "300"))
        polling_interval_seconds = float(os.environ.get("JOB_WAIT_POLLING_INTERVAL_SECONDS", "1.0"))
    except ValueError:
        timeout_seconds = 300
        polling_interval_seconds = 1.0

    start_time = time.time()

    while True:
        if time.time() - start_time > timeout_seconds:
            return {'state': 'timeout', 'job_id': job_id, 'message': f"Job {job_id} did not complete within {timeout_seconds} seconds."}

        status = fetch_job_status(job_id)

        if status['state'] == 'done':
            return status

        time.sleep(polling_interval_seconds)
