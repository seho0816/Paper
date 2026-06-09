def authorize_refund(
    account_id: str,
    payment_id: str,
) -> bool:
    decision = policy_service.check(
        account_id,
        "payment.refund",
        payment_id,
    )

    if decision is None:
        return False

    return bool(
        decision
    )
