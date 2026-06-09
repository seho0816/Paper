import json


def handle_payment_webhook(
    raw_body: bytes,
) -> dict:
    event = json.loads(
        raw_body,
    )

    if event["type"] == "payment.succeeded":
        mark_order_paid(
            event["order_id"],
        )

    return {
        "status": "ok",
    }
