from pathlib import Path


def write_payment_snapshot(
    request_id: str,
    body: bytes,
) -> Path:
    path = Path(
        "/tmp"
    ) / (
        "payment-"
        + request_id
        + ".json"
    )
    path.write_bytes(
        body
    )

    return path
