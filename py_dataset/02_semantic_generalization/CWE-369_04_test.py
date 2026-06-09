from decimal import Decimal


def average_refund(
    total_refund: Decimal,
    refund_count: int,
) -> Decimal:
    return (
        total_refund
        / Decimal(
            refund_count
        )
    )
