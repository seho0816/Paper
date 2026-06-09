def find_orders(
    engine,
    status: str,
) -> str:
    query = (
        "for $order in collection('orders')/order "
        "where $order/status = '"
        + status
        + "' return $order"
    )

    return engine.query(
        query
    )
