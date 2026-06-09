def search_products(
    document,
    maximum_price: str,
) -> list:
    expression = (
        "//product[price <= "
        + maximum_price
        + "]"
    )

    return document.xpath(
        expression
    )
