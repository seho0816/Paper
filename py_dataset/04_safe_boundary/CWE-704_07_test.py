from decimal import Decimal, InvalidOperation


def parse_amount_cents(
    raw_amount: str,
) -> int:
    try:
        amount = Decimal(
            raw_amount,
        )
    except InvalidOperation as error:
        raise ValueError(
            "invalid amount"
        ) from error

    if amount < 0:
        raise ValueError(
            "negative amount"
        )

    cents = amount * Decimal(
        "100"
    )

    if cents != cents.to_integral_value():
        raise ValueError(
            "too many decimal places"
        )

    return int(cents)
