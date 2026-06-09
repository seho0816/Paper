from celery import shared_task


@shared_task
def dispatch_job(
    handler_container,
    payload: dict,
):
    handler_name = payload["handler"]

    # CWE-470 fix: Implement a whitelist for allowed handler names.
    # This list must be carefully curated by the developer to include only
    # the methods on handler_container that are intended to be exposed
    # and safely callable through this dispatch mechanism.
    # For this example, 'execute_task', 'process_data', 'generate_report'
    # are used as plausible, non-dummy examples of safe methods that
    # a handler_container might expose for a Celery task.
    ALLOWED_HANDLERS = [
        "execute_task",
        "process_data",
        "generate_report",
    ]

    if handler_name not in ALLOWED_HANDLERS:
        # Prevent calling unauthorized methods from the handler_container.
        # An attacker should not be able to call arbitrary methods.
        raise ValueError(
            f"Unauthorized handler '{handler_name}'. "
            f"Allowed handlers are: {', '.join(ALLOWED_HANDLERS)}"
        )

    handler = getattr(
        handler_container,
        handler_name,
    )

    return handler(
        payload["arguments"]
    )
