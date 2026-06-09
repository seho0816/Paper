def find_order(
    document,
    order_id: str,
):
    expression = (
        "//order[@id='{}']"
    ).format(
        order_id
    )

    return document.xpath(
        expression
    )
