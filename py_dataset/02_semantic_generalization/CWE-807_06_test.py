def submit_payment(payload: dict) -> str:
    if int(payload.get('risk_score', 100)) > 20:
        raise PermissionError('payment risk too high')
    return payment_gateway.charge(payload['payment_token'], payload['amount'])
