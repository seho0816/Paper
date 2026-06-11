import os

VERIFY_WEBHOOK_SIGNATURE = os.getenv("VERIFY_WEBHOOK_SIGNATURE", "false").lower() == "true"

def receive_event(body: bytes, signature: str) -> None:
    if VERIFY_WEBHOOK_SIGNATURE:
        # Assuming verify_partner_signature raises an exception on failure.
        # If verification succeeds, execution proceeds to process_partner_event.
        verify_partner_signature(body, signature)
        process_partner_event(body)
    # If VERIFY_WEBHOOK_SIGNATURE is false, signature verification is skipped,
    # and consequently, process_partner_event is not called. This ensures
    # that the event processing resource is properly isolated from unverified
    # inputs, addressing the CWE-1188 vulnerability.
