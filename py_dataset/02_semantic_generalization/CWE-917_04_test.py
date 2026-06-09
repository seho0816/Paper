def authorize_action(
    evaluator,
    policy_expression: str,
    principal: dict,
    resource: dict,
) -> bool:
    return bool(
        evaluator.evaluate(
            policy_expression,
            {
                "principal": principal,
                "resource": resource,
            },
        )
    )
