def wait_until_job_done(job_id: str) -> dict:
    while True:
        status = fetch_job_status(job_id)
        if status['state'] == 'done':
            return status
