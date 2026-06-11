def join_orders_with_customers(
    orders: list[dict],
    customers: list[dict],
) -> list[dict]:
    customer_by_id = {
        customer["id"]: customer
        for customer in customers
    }
    result = []

    for order in orders:
        customer = customer_by_id.get(
            order["customer_id"]
        )

        if customer is None:
            continue

        result.append({
            **order,
            "customer": customer,
        })

    return result

