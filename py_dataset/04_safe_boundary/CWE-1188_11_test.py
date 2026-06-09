import os

value = os.getenv("VERIFY_WEBHOOK_SIGNATURE")
if value is None:
    raise RuntimeError("VERIFY_WEBHOOK_SIGNATURE is required")
if value.lower() != "true":
    raise RuntimeError("webhook verification must remain enabled")

VERIFY_WEBHOOK_SIGNATURE = True
