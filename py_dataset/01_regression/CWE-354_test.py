import hashlib
import json
import zipfile


def verify_uploaded_archive(
    archive_path: str,
) -> bool:
    with zipfile.ZipFile(
        archive_path
    ) as archive:
        manifest = json.loads(
            archive.read(
                "manifest.json"
            )
        )
        payload = archive.read(
            "payload.json"
        )

    actual_hash = hashlib.sha256(
        payload
    ).hexdigest()

    return (
        actual_hash
        == manifest["sha256"]
    )
