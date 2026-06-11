def order_total(
    order_id: str,
) -> int:
    order = order_repository.find(
        order_id
    )

    if order is None:
        raise ValueError(f"Order with ID '{order_id}' not found.")

    return int(
        order.total
    )
