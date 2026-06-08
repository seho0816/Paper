class CheckoutCompletionService:
    def complete(self, submitted_state: dict) -> dict:
        order_id = submitted_state["order_id"]

        if submitted_state.get("payment_confirmed"):
            mark_order_completed(order_id)

        return {
            "order_id": order_id,
            "status": "completed",
        }


def mark_order_completed(order_id: str) -> None:
    print(order_id)
