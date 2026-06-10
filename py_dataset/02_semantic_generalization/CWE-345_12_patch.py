import json
import os
import hmac
import hashlib
from typing import Any


orders: dict[str, str] = {}


WEBHOOK_SIGNATURE_HEADER = "X-Webhook-Signature"
WEBHOOK_SECRET_ENV_VAR = "PAYMENT_WEBHOOK_SECRET"


def mark_order_paid(order_id: str) -> None:
    orders[order_id] = "PAID"


def parse_event(raw_body: bytes) -> dict[str, Any]:
    return json.loads(raw_body.decode("utf-8"))


def handle_payment_webhook(raw_body: bytes, headers: dict[str, str]) -> dict[str, str]:
    try:
        webhook_secret = os.environ[WEBHOOK_SECRET_ENV_VAR].encode('utf-8')
    except KeyError:
        return {"status": "error", "message": "Webhook secret not configured."}

    received_signature = headers.get(WEBHOOK_SIGNATURE_HEADER)

    if not received_signature:
        return {"status": "error", "message": "Missing webhook signature header."}

    computed_signature = hmac.new(webhook_secret, raw_body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(received_signature, computed_signature):
        return {"status": "error", "message": "Invalid webhook signature."}

    event = parse_event(raw_body)

    if event["type"] == "payment.succeeded":
        mark_order_paid(event["order_id"])

    return {
        "status": "ok",
    }


def main():
    fake_event = {
        "type": "payment.succeeded",
        "order_id": "ORDER-1001",
    }

    result = handle_payment_webhook(
        json.dumps(fake_event).encode("utf-8"),
        headers={},
    )

    print(result)
    print(orders)


if __name__ == "__main__":
    main()
