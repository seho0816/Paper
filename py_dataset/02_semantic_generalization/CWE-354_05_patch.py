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

        # CWE-354 mitigation: Ensure both manifest.json and payload.bin
        # are present in the archive and are regular files.
        # If extractfile returns None, the member was not found or
        # was not a regular file (e.g., a symlink or device file),
        # which would represent an "improper state" for verification.
        if manifest_file is None or payload_file is None:
            return False

        try:
            manifest = json.loads(
                manifest_file.read()
            )
        except json.JSONDecodeError:
            # CWE-354 mitigation: The manifest file must contain valid JSON.
            # If it's malformed, it indicates an "improper state" for verification.
            return False

        payload = payload_file.read()

    # CWE-354 mitigation: Ensure the parsed manifest is a dictionary
    # and contains the expected 'sha256' key.
    # A manifest lacking this critical information is in an "improper state".
    if not isinstance(manifest, dict) or "sha256" not in manifest:
        return False

    return (
        hashlib.sha256(
            payload
        ).hexdigest()
        == manifest["sha256"]
    )
