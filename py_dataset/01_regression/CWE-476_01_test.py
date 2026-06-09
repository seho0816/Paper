def order_total(
    order_id: str,
) -> int:
    order = order_repository.find(
        order_id
    )

    return int(
        order.total
    )
