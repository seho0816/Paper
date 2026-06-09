def publish_payment_event(order_id: str, card_token: str, amount: int) -> None:
    event_bus.publish(
        "payment_completed",
        {
            "order_id": order_id,
            "amount": amount,
        },
    )
