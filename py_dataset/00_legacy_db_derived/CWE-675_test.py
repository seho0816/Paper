class RefundApprovalService:
    def approve(self, order_id: str, requested_amount: int) -> dict:
        first_refund = refund_payment(order_id, requested_amount)
        second_refund = refund_payment(order_id, requested_amount)

        store_refund_result(order_id, second_refund)

        return {
            "refund_reference": second_refund,
        }


def refund_payment(order_id: str, amount: int) -> str:
    return f"{order_id}:{amount}"


def store_refund_result(order_id: str, refund_reference: str) -> None:
    print(order_id, refund_reference)
