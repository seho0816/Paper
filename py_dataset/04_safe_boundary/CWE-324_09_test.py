from datetime import datetime, timezone


def select_active_key(
    keys: list[dict],
) -> dict:
    now = datetime.now(
        timezone.utc
    )

    for key in keys:
        expires_at = datetime.fromisoformat(
            key["expires_at"]
        )

        if (
            key.get(
                "active",
                False,
            )
            and expires_at > now
        ):
            return key

    raise RuntimeError(
        "no active signing key"
    )
