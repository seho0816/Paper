import time

def wait_for_job(payload: dict) -> str:
    # CWE-606: Unchecked Input for Loop Condition
    # Mitigation: Limit the maximum number of attempts to prevent Denial of Service (DoS)
    # in case a malicious or erroneous 'poll_attempts' value is provided.
    MAX_POLL_ATTEMPTS = 120 # A reasonable maximum to limit polling duration (e.g., 2 minutes)

    # Ensure the number of attempts is an integer and does not exceed the predefined maximum.
    attempts = min(int(payload['poll_attempts']), MAX_POLL_ATTEMPTS)

    for _ in range(attempts):
        # job_client is assumed to be an externally defined client object.
        status = job_client.status(payload['job_id'])
        if status == 'complete':
            return status
        time.sleep(1)
    return 'pending'
