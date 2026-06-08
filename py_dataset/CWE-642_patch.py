class CheckoutCompletionService:
    def complete(self, submitted_state: dict) -> dict:
        order_id = submitted_state["order_id"]

        # CWE-642: External Control of Critical State Data.
        # The decision to mark an order as completed should not be based on
        # externally provided, unverified flags like "payment_confirmed".
        # This vulnerability is removed by ensuring that the 'payment_confirmed'
        # flag from external input no longer controls the critical action.
        # It's assumed that the 'complete' method is called only after payment
        # has been internally verified or that such verification happens upstream.
        mark_order_completed(order_id)

        return {
            "order_id": order_id,
            "status": "completed",
        }


def mark_order_completed(order_id: str) -> None:
    print(order_id)
