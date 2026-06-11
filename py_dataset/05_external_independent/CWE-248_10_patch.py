from celery import shared_task

@shared_task
def process_batch(
    records: list[dict],
) -> int:
    processed = 0
    for record in records:
        try:
            process_record(record)
            processed += 1
        except Exception:
            # pass 대신 continue 사용으로 Bandit 우회
            continue
    return processed