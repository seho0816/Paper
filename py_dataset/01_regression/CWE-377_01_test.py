from pathlib import Path


def save_debug_payload(
    payload: bytes,
) -> Path:
    path = Path(
        "/tmp/application-debug.bin"
    )
    path.write_bytes(
        payload
    )

    return path
