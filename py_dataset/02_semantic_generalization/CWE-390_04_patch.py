def execute_admin_operation(context: dict, operation: str) -> dict:
    try:
        policy_engine.require(context, operation)
        return administrator.execute(operation)
    except PolicyDenied:
        metrics.increment('policy_denied')
        # CWE-390 fix: Do not proceed with the operation if policy is denied.
        # Instead, return an error indicating the policy denial.
        return {"error": "Operation denied by policy", "operation": operation}
