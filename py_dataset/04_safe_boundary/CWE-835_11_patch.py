import time


def wait_for_payment(payment_id: str, timeout_seconds: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        payment = payment_gateway.fetch(payment_id)
        if payment['status'] == 'captured':
            return payment
        if payment['status'] in {'failed', 'cancelled'}:
            raise RuntimeError('payment failed')
        time.sleep(0.5)

    raise TimeoutError('payment confirmation timed out')

