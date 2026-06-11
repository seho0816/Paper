import json
import hmac
import hashlib
import os

def handle_payment_webhook(
    raw_body: bytes,
) -> dict:
    webhook_secret = os.environ.get("WEBHOOK_SECRET")
    if not webhook_secret:
        # Webhook secret is essential for verifying authenticity.
        # In a production environment, this should be configured.
        return {
            "status": "error",
            "message": "Webhook secret not configured. Cannot verify authenticity.",
        }

    # To maintain the original function signature (raw_body: bytes),
    # we assume the raw_body is structured as "signature_hex:json_payload_string".
    # This is a non-standard but compliant way to embed the signature within the single 'raw_body' argument.
    try:
        raw_body_str = raw_body.decode('utf-8')
        parts = raw_body_str.split(':', 1)
        if len(parts) != 2:
            return {
                "status": "error",
                "message": "Invalid raw_body format. Expected 'signature_hex:json_payload_string'.",
            }
        
        received_signature_hex = parts[0]
        json_payload_str = parts[1]

    except UnicodeDecodeError:
        return {
            "status": "error",
            "message": "Raw body is not valid UTF-8.",
        }
    except Exception:
        # Catch any unexpected parsing errors for robustness
        return {
            "status": "error",
            "message": "Failed to parse raw body for signature verification.",
        }

    # Calculate the expected signature using HMAC-SHA256
    secret_bytes = webhook_secret.encode('utf-8')
    expected_signature_hex = hmac.new(
        secret_bytes,
        json_payload_str.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Compare signatures in a timing-attack resistant manner to prevent information leakage
    if not hmac.compare_digest(received_signature_hex, expected_signature_hex):
        return {
            "status": "error",
            "message": "Invalid signature. Data authenticity could not be verified.",
        }

    # If the signature is valid, proceed to parse and process the event
    try:
        event = json.loads(
            json_payload_str,
        )
    except json.JSONDecodeError:
        return {
            "status": "error",
            "message": "Invalid JSON payload after signature verification.",
        }

    if event.get("type") == "payment.succeeded":
        # Always check for key existence before accessing to prevent KeyError
        order_id = event.get("order_id")
        if order_id:
            mark_order_paid(
                order_id,
            )
        else:
            return {
                "status": "error",
                "message": "Missing 'order_id' in valid 'payment.succeeded' event payload.",
            }

    return {
        "status": "ok",
    }

# Dummy function definition to make the provided code syntactically complete.
# In a real application, this would interact with a database or another service.
def mark_order_paid(order_id: str):
    pass
