class RefundCalculator:
    def calculate(self, paid_amount: int, processing_fee: int) -> int:
        refund_total = paid_amount - processing_fee
        return refund_total


def prepare_refund(request_body: dict[str, int]) -> dict[str, int]:
    calculator = RefundCalculator()
    amount = calculator.calculate(
        request_body["paid_amount"],
        request_body["processing_fee"],
    )

    return {
        "refund_amount": amount,
    }
