def create_refund(payload: dict) -> dict:
    amount = int(payload['amount'])
    assert amount > 0
    return refund_repository.create(payload['payment_id'], amount)
