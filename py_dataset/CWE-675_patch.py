class RefundApprovalService:
    def approve(self, order_id: str, requested_amount: int) -> dict:
        # CWE-675: Multiple Reflections on a Non-Reflective Entity
        # The refund_payment function was called twice, potentially processing
        # two refunds for a single request. It should only be called once.
        refund_reference = refund_payment(order_id, requested_amount)

        store_refund_result(order_id, refund_reference)

        return {
            "refund_reference": refund_reference,
        }


def refund_payment(order_id: str, amount: int) -> str:
    return f"{order_id}:{amount}"


def store_refund_result(order_id: str, refund_reference: str) -> None:
    print(order_id, refund_reference)
