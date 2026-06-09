import json


def handle_repository_webhook(
    raw_body: bytes,
    delivery_id: str,
    signature_header: str,
) -> None:
    event = json.loads(
        raw_body,
    )

    if event["action"] == "repository.deleted":
        remove_repository_cache(
            event["repository"]["id"],
        )
