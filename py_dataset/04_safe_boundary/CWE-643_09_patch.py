NODE_EXPRESSIONS = {
    "employee": "//employee/name/text()",
    "department": "//department/name/text()",
}


def select_nodes(
    document,
    node_type: str,
) -> list[str]:
    expression = NODE_EXPRESSIONS.get(
        node_type
    )

    if expression is None:
        raise ValueError(
            "unsupported node type"
        )

    return document.xpath(
        expression
    )

