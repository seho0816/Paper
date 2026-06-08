import json
from urllib.parse import parse_qs


def parse_payload(content_type: str, raw_body: bytes) -> dict:
    if content_type == "application/json":
        return json.loads(raw_body.decode("utf-8"))

    parsed = parse_qs(raw_body.decode("utf-8"))
    return {
        key: values[-1]
        for key, values in parsed.items()
    }


class ProfileUpdateService:
    def update(self, content_type: str, raw_body: bytes) -> dict:
        # Parse the payload once using the actual content_type for consistent interpretation.
        # This prevents an attacker from sending a payload that is interpreted differently
        # for validation versus persistence (e.g., JSON for validation, form data for persistence),
        # bypassing the "role update not allowed" check.
        parsed_data = parse_payload(content_type, raw_body)

        if parsed_data.get("role") == "administrator":
            raise PermissionError("role update not allowed")

        return persist_profile(parsed_data)


def persist_profile(payload: dict) -> dict:
    return payload
