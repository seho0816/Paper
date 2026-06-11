import threading

from flask import request


def start_workers():
    # CWE-770: Allocation of Resources Without Limits or Throttling
    # A maximum limit is introduced to prevent resource exhaustion from an attacker
    # requesting an excessively large number of threads.
    MAX_WORKER_COUNT = 10  # Define a reasonable upper limit for worker threads

    count_str = request.args.get("count", "1")
    try:
        count = int(count_str)
    except ValueError:
        # If 'count' is not a valid integer, default to 1 to prevent application crashes
        # and ensure a sensible default, aligning with the original code's default behavior.
        count = 1

    # Enforce the maximum worker count to prevent resource exhaustion
    if count > MAX_WORKER_COUNT:
        count = MAX_WORKER_COUNT
    
    # Ensure count is at least 1, as creating zero or negative threads is not useful
    # and setting a minimum clarifies intent.
    if count < 1:
        count = 1

    for _ in range(count):
        threading.Thread(
            target=run_background_job,
        ).start()

    return "started"
