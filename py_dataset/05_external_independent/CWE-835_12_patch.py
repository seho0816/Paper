import time
from celery import shared_task

@shared_task
def wait_for_conversion(conversion_id: str) -> dict:
    # CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')
    # The original loop could potentially run indefinitely if the conversion
    # never reaches a 'finished' state, leading to resource exhaustion.
    # To mitigate this, a maximum number of attempts (or a timeout) is added.
    # If the conversion doesn't finish within these attempts, an exception is raised.
    max_attempts = 150  # Roughly 5 minutes (150 attempts * 2 seconds/attempt = 300 seconds)
    attempt_count = 0

    while True:
        if attempt_count >= max_attempts:
            # Raise an exception to indicate that the conversion timed out.
            # This prevents the task from running indefinitely and consuming resources.
            raise TimeoutError(f"Conversion {conversion_id} timed out after {max_attempts} attempts.")

        # Assumes 'conversion_client' is globally available or imported elsewhere in the application context.
        result = conversion_client.status(
            conversion_id
        )
        if result['state'] == 'finished':
            return result
        
        attempt_count += 1
        time.sleep(2)
