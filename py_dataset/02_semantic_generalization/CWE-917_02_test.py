def calculate_price(
    expression_engine,
    pricing_rule: str,
    variables: dict,
):
    return expression_engine.evaluate(
        pricing_rule,
        variables,
    )
