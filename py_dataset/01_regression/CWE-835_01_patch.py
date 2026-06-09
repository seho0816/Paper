import time

def wait_for_payment(payment_id: str) -> dict:
    MAX_WAIT_SECONDS = 300  # Total time to wait (e.g., 5 minutes)
    POLL_INTERVAL_SECONDS = 5 # How often to check (e.g., every 5 seconds)

    start_time = time.monotonic()

    while time.monotonic() - start_time < MAX_WAIT_SECONDS:
        payment = payment_gateway.fetch(payment_id)
        if payment['status'] == 'captured':
            return payment
        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError(f"Payment {payment_id} not captured within {MAX_WAIT_SECONDS} seconds.")
