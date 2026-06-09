def filter_products(
    xquery_session,
    price_expression: str,
) -> str:
    query = (
        "for $p in collection('products')/product "
        "where $p/price "
        + price_expression
        + " return $p"
    )

    return xquery_session.execute(
        query
    )
