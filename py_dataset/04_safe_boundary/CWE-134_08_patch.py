def render_order_message(
    customer_name: str,
    order_id: str,
) -> str:
    return (
        "Hello {name}, your order "
        "{order_id} is ready."
    ).format(
        name=customer_name,
        order_id=order_id,
    )

