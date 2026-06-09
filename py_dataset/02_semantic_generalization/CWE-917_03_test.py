def filter_orders(
    rule_engine,
    submitted_rule: str,
    orders: list[dict],
) -> list[dict]:
    rule = rule_engine.compile(
        submitted_rule
    )

    return [
        order
        for order in orders
        if rule.matches(
            order
        )
    ]
