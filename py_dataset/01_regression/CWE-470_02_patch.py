ALLOWED_OPERATIONS = {
    "execute_command",
    "query_database",
    "generate_report",
}

def dispatch_operation(
    service,
    operation_name: str,
    payload: dict,
):
    if operation_name not in ALLOWED_OPERATIONS:
        raise ValueError(f"Operation '{operation_name}' is not allowed.")

    handler = getattr(
        service,
        operation_name,
    )

    return handler(
        payload
    )
