from celery import shared_task


@shared_task
def process_batch(
    records: list[dict],
) -> int:
    processed = 0

    for record in records:
        process_record(
            record
        )
        processed += 1

    return processed
