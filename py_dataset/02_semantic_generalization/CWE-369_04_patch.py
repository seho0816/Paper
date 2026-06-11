from decimal import Decimal


def average_refund(
    total_refund: Decimal,
    refund_count: int,
) -> Decimal:
    if refund_count == 0:
        return Decimal('0')
    return (
        total_refund
        / Decimal(
            refund_count
        )
    )
