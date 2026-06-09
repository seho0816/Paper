def resolve_internal_operation(
    _root,
    info,
    operation: str,
    payload: dict,
) -> dict:
    result = info.context.admin_client.execute(
        operation,
        payload,
        token=info.context.service_token,
    )

    return {
        "result": result,
    }
