import json
import hmac
import hashlib
import os


def handle_repository_webhook(
    raw_body: bytes,
    delivery_id: str,
    signature_header: str,
) -> None:
    webhook_secret = os.environ.get("WEBHOOK_SECRET")
    if not webhook_secret:
        raise ValueError("WEBHOOK_SECRET environment variable not set.")

    if not signature_header.startswith("sha256="):
        raise ValueError("Invalid signature header format: must start with 'sha256='.")

    expected_signature = signature_header.split("=")[1].strip()

    computed_hmac = hmac.new(
        webhook_secret.encode('utf-8'),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_hmac, expected_signature):
        raise PermissionError("Webhook signature verification failed: Payload is not authentic.")

    event = json.loads(
        raw_body,
    )

    if event["action"] == "repository.deleted":
        remove_repository_cache(
            event["repository"]["id"],
        )
