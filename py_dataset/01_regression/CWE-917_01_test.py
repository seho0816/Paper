from simpleeval import simple_eval


def evaluate_access_rule(
    expression: str,
    context: dict,
):
    return simple_eval(
        expression,
        names=context,
    )
