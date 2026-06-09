class RefundWorkflow:
    def request_refund(self, order: dict, reason: str) -> dict:
        order["refund"] = {
            "reason": reason,
            "state": "requested",
        }
        order["order_state"] = "refund_pending"
        return order


def main() -> None:
    order = {
        "id": "ORDER-100",
        "payment_state": "paid",
        "delivery_state": "preparing",
    }
    workflow = RefundWorkflow()
    print(workflow.request_refund(order, "changed mind"))


if __name__ == "__main__":
    main()
