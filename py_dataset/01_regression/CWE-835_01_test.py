def wait_for_payment(payment_id: str) -> dict:
    while True:
        payment = payment_gateway.fetch(payment_id)
        if payment['status'] == 'captured':
            return payment
