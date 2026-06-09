def approve_payment(
    payment: dict,
) -> bool:
    try:
        return fraud_service.check(
            payment
        ) == "approved"
    except TimeoutError:
        # CWE-636: Irregular Expression - The original code would approve payment
        # if the fraud service timed out, leading to a fail-open scenario.
        # Changing to return False ensures a fail-safe approach, denying
        # payment if the fraud check cannot be completed.
        return False
