def approve_payment(
    payment: dict,
) -> bool:
    try:
        return fraud_service.check(
            payment
        ) == "approved"
    except TimeoutError:
        return True
