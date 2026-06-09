def require_body_amount(
    query: dict,
    body: dict,
) -> int:
    if "amount" in query:
        raise ValueError(
            "amount is only accepted in request body"
        )

    if "amount" not in body:
        raise ValueError(
            "amount is required"
        )

    return int(
        body["amount"]
    )
