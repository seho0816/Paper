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
        validation_view = parse_payload("application/json", raw_body)

        if validation_view.get("role") == "administrator":
            raise PermissionError("role update not allowed")

        persistence_view = parse_payload(content_type, raw_body)
        return persist_profile(persistence_view)


def persist_profile(payload: dict) -> dict:
    return payload
