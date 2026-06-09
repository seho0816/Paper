def select_nodes(
    document,
    node_name: str,
) -> list:
    expression = (
        "//"
        + node_name
        + "/text()"
    )

    return document.xpath(
        expression
    )
