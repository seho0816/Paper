import hashlib
import json


def verify_release(
    manifest_body: bytes,
    manifest_signature: bytes,
    package_body: bytes,
    public_key,
) -> dict:
    public_key.verify(
        manifest_signature,
        manifest_body,
    )
    manifest = json.loads(
        manifest_body
    )
    actual_digest = hashlib.sha256(
        package_body
    ).hexdigest()

    if actual_digest != manifest[
        "sha256"
    ]:
        raise PermissionError(
            "package digest mismatch"
        )

    return manifest
