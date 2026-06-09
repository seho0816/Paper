def create_payment(
    query: dict,
    body: dict,
) -> int:
    amount = int(
        query.get(
            "amount",
            0,
        )
    )

    if "amount" in body:
        amount = int(
            body["amount"]
        )

    return charge_payment(
        amount
    )
