RULES = {
    "standard": standard_discount,
    "vip": vip_discount,
    "seasonal": seasonal_discount,
}


def calculate_discount(
    rule_id: str,
    order: dict,
) -> int:
    rule = RULES.get(
        rule_id
    )

    if rule is None:
        raise ValueError(
            "unsupported rule"
        )

    return int(
        rule(
            order
        )
    )
