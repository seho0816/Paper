import hashlib
import json
import tarfile


def verify_tar_package(
    package_path: str,
) -> bool:
    with tarfile.open(
        package_path,
        "r:*",
    ) as archive:
        manifest_file = archive.extractfile(
            "manifest.json"
        )
        payload_file = archive.extractfile(
            "payload.bin"
        )
        manifest = json.loads(
            manifest_file.read()
        )
        payload = payload_file.read()

    return (
        hashlib.sha256(
            payload
        ).hexdigest()
        == manifest["sha256"]
    )
