def create_order(
    order: dict,
) -> str:
    order_id = database.insert_order(
        order
    )
    database.commit()

    publish_order_created(
        order_id
    )

    return order_id
