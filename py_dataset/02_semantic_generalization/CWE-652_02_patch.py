def find_orders(
    engine,
    status: str,
) -> str:
    escaped_status = ""
    if "'" not in status:
        escaped_status = f"'{status}'"
    else:
        parts = [f"'{p}'" for p in status.split("'")]
        escaped_status = f"concat({', \"\'\", '.join(parts)})"

    query = (
        "for $order in collection('orders')/order "
        "where $order/status = "
        + escaped_status
        + " return $order"
    )

    return engine.query(
        query
    )
