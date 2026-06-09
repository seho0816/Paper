import json
import hmac
import hashlib
import os


def consume_inventory_event(
    message_body: bytes,
    signature: str,
) -> None:
    hmac_secret_key = os.environ["INVENTORY_HMAC_SECRET_KEY"].encode('utf-8')

    calculated_hmac = hmac.new(
        hmac_secret_key,
        message_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(calculated_hmac, signature):
        return

    event = json.loads(
        message_body,
    )

    if event["type"] == "inventory.adjusted":
        update_inventory(
            event["sku"],
            int(event["quantity"]),
        )
