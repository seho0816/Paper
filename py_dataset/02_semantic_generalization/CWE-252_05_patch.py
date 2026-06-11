def create_order(
    order: dict,
) -> str:
    order_id = database.insert_order(
        order
    )
    commit_result = database.commit()

    if commit_result:
        publish_order_created(
            order_id
        )
        return order_id
    else:
        raise RuntimeError("Failed to commit order transaction.")
