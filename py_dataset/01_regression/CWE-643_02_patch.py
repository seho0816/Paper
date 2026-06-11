def find_order(
    document,
    order_id: str,
):
    expression = (
        "//order[@id=$order_id_var]"
    )

    return document.xpath(
        expression,
        order_id_var=order_id
    )
