import ast
import operator


OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
}
ALLOWED_NAMES = {
    "order_total",
    "customer_level",
}


def validate_expression(
    expression: str,
) -> ast.Expression:
    tree = ast.parse(
        expression,
        mode="eval",
    )

    for node in ast.walk(
        tree
    ):
        if isinstance(
            node,
            ast.Name,
        ) and node.id not in ALLOWED_NAMES:
            raise ValueError(
                "unknown variable"
            )

        if isinstance(
            node,
            (
                ast.Call,
                ast.Attribute,
                ast.Subscript,
            ),
        ):
            raise ValueError(
                "unsupported expression"
            )

        if isinstance(
            node,
            ast.BinOp,
        ) and type(node.op) not in OPERATORS:
            raise ValueError(
                "unsupported operator"
            )

    return tree

