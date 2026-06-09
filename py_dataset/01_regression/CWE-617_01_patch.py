def create_refund(payload: dict) -> dict:
    amount = int(payload['amount'])
    if amount <= 0:
        raise ValueError("Refund amount must be positive.")
    return refund_repository.create(payload['payment_id'], amount)
