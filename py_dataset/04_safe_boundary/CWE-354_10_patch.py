import hashlib
import json


def verify_signed_package(
    manifest_body: bytes,
    manifest_signature: bytes,
    payload: bytes,
    trusted_public_key,
) -> bool:
    trusted_public_key.verify(
        manifest_signature,
        manifest_body,
    )
    manifest = json.loads(
        manifest_body
    )
    actual = hashlib.sha256(
        payload
    ).hexdigest()

    return (
        actual
        == manifest["sha256"]
    )

