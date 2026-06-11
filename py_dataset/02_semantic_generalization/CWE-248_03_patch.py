import json


def handle_webhook(
    raw_body: bytes,
) -> dict:
    try:
        event = json.loads(
            raw_body
        )
    except json.JSONDecodeError:
        # CWE-248: Uncaught Exception - Catches JSON parsing errors
        # Returns a structured error response instead of letting the application crash
        return {"error": "Invalid JSON payload provided"}

    return process_webhook(
        event
    )
