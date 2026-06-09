def consume_job(
    queue,
) -> None:
    job = queue.get()
    try:
        execute_job(
            job
        )
    except Exception:
        queue.task_done()
        raise
    finally:
        queue.task_done()
