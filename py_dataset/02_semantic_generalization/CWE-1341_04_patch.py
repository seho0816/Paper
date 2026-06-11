def consume_job(
    queue,
) -> None:
    job = queue.get()
    try:
        execute_job(
            job
        )
    except Exception:
        raise
    finally:
        queue.task_done()
