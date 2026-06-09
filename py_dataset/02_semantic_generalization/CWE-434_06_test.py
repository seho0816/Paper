import base64
from pathlib import Path


def save_attachment(payload: dict) -> str:
    filename = str(payload["filename"])
    encoded_content = str(payload["content"])
    content = base64.b64decode(
        encoded_content,
    )

    destination = (
        Path("/srv/web/public/attachments")
        / filename
    )
    destination.write_bytes(content)

    return str(destination)
