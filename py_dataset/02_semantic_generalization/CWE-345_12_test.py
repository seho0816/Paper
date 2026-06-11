import json
from typing import Any


orders: dict[str, str] = {}


def mark_order_paid(order_id: str) -> None:
    orders[order_id] = "PAID"


def parse_event(raw_body: bytes) -> dict[str, Any]:
    return json.loads(raw_body.decode("utf-8"))


def handle_payment_webhook(raw_body: bytes, headers: dict[str, str]) -> dict[str, str]:
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
