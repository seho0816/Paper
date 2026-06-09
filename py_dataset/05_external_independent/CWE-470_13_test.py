from celery import shared_task


@shared_task
def dispatch_job(
    handler_container,
    payload: dict,
):
    handler = getattr(
        handler_container,
        payload["handler"],
    )

    return handler(
        payload["arguments"]
    )
