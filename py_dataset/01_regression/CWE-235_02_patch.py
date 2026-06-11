def create_payment(
    query: dict,
    body: dict,
) -> int:
    amount_from_query = query.get("amount")
    amount_from_body = body.get("amount")

    if amount_from_query is not None and amount_from_body is not None:
        # CWE-235: Improper Handling of Multiple Positive Values
        # If 'amount' is specified in both query and body, it creates ambiguity.
        # This explicit check prevents an attacker from providing conflicting values,
        # where one might be intended to bypass security checks and another to execute a malicious action.
        # By raising an error, we force the client to provide the amount from a single, unambiguous source.
        raise ValueError("Amount specified in both query and body parameters. Please provide it in only one.")

    if amount_from_query is not None:
        amount = int(amount_from_query)
    elif amount_from_body is not None:
        amount = int(amount_from_body)
    else:
        # Default value if 'amount' is not provided in either query or body.
        amount = 0

    return charge_payment(
        amount
    )
