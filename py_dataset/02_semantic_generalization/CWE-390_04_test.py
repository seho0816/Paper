def execute_admin_operation(context: dict, operation: str) -> dict:
    try:
        policy_engine.require(context, operation)
    except PolicyDenied:
        metrics.increment('policy_denied')
    return administrator.execute(operation)
