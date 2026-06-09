def resolve_calculate(
    _root,
    info,
    expression: str,
) -> dict:
    result = info.context.expression_engine.evaluate(
        expression,
        info.context.variables,
    )

    return {
        "result": result,
    }
