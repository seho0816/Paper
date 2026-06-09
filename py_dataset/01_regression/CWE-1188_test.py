import os

VERIFY_WEBHOOK_SIGNATURE = os.getenv("VERIFY_WEBHOOK_SIGNATURE", "false").lower() == "true"

def receive_event(body: bytes, signature: str) -> None:
    if VERIFY_WEBHOOK_SIGNATURE:
        verify_partner_signature(body, signature)
    process_partner_event(body)
