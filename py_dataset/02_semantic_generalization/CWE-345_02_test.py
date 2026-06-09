import json


def consume_inventory_event(
    message_body: bytes,
    signature: str,
) -> None:
    event = json.loads(
        message_body,
    )

    if event["type"] == "inventory.adjusted":
        update_inventory(
            event["sku"],
            int(event["quantity"]),
        )
