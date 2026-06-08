class RefundWorkflow:
    # CWE-841 Fix: Enforce required workflow steps in the correct order.
    # A refund must only be allowed when:
    #   1. The order has been paid (payment_state == "paid")
    #   2. The item has not already been delivered (delivery_state != "delivered")
    # Skipping these checks allows bypassing the intended business logic.

    _REFUNDABLE_PAYMENT_STATES  = {"paid"}
    _NON_REFUNDABLE_DELIVERY_STATES = {"delivered", "returned"}

    def request_refund(self, order: dict, reason: str) -> dict:
        payment_state  = order.get("payment_state")
        delivery_state = order.get("delivery_state")

        # Step 1: Verify payment state allows refund
        if payment_state not in self._REFUNDABLE_PAYMENT_STATES:
            raise ValueError(
                f"Refund not allowed: order has not been paid "
                f"(payment_state={payment_state!r})"
            )

        # Step 2: Verify delivery state allows refund
        if delivery_state in self._NON_REFUNDABLE_DELIVERY_STATES:
            raise ValueError(
                f"Refund not allowed: item already {delivery_state!r}"
            )

        # Step 3: Apply refund only after all checks pass
        order["refund"] = {
            "reason": reason,
            "state":  "requested",
        }
        order["order_state"] = "refund_pending"
        return order


def main() -> None:
    order = {
        "id":             "ORDER-100",
        "payment_state":  "paid",
        "delivery_state": "preparing",
    }
    workflow = RefundWorkflow()
    print(workflow.request_refund(order, "changed mind"))


if __name__ == "__main__":
    main()