def join_orders_with_customers(
    orders: list[dict],
    customers: list[dict],
) -> list[dict]:
    result = []

    for order in orders:
        customer = next(
            (item for item in customers if item["id"] == order["customer_id"]),
            None
        )
        result.append({
            **order,
            "customer": customer,
        })

    return result
