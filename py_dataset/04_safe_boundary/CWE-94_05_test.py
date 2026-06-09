import operator

OPERATIONS = {
    "add": operator.add,
    "subtract": operator.sub,
    "multiply": operator.mul,
    "divide": operator.truediv,
}


def calculate(
    operation_name: str,
    left: float,
    right: float,
) -> float:
    operation = OPERATIONS.get(
        operation_name,
    )

    if operation is None:
        raise ValueError(
            "unsupported operation"
        )

    return float(
        operation(
            left,
            right,
        )
    )
