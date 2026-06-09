def dispatch_operation(
    service,
    operation_name: str,
    payload: dict,
):
    handler = getattr(
        service,
        operation_name,
    )

    return handler(
        payload
    )
