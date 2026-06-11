def search_products(
    document,
    maximum_price: str,
) -> list:
    expression = (
        "//product[price <= $max_price]"
    )

    return document.xpath(
        expression,
        max_price=maximum_price
    )
