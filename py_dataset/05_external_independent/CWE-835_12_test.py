import time
from celery import shared_task

@shared_task
def wait_for_conversion(conversion_id: str) -> dict:
    while True:
        result = conversion_client.status(
            conversion_id
        )
        if result['state'] == 'finished':
            return result
        time.sleep(2)
