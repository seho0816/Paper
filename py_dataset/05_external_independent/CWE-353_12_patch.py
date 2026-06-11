from celery import shared_task
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

# Module-level configuration for signature verification
# Load partner's public key from environment variable. It's assumed to be in PEM format.
# This critical configuration will be loaded once at module import time.
PARTNER_PUBLIC_KEY_ENV = os.environ.get("PARTNER_PUBLIC_KEY")

if not PARTNER_PUBLIC_KEY_ENV:
    raise RuntimeError("PARTNER_PUBLIC_KEY environment variable is not set. Cannot configure signature verification.")

try:
    _partner_public_key = serialization.load_pem_public_key(
        PARTNER_PUBLIC_KEY_ENV.encode('utf-8'),
        backend=default_backend()
    )
except Exception as e:
    raise RuntimeError(f"Failed to load partner public key from environment: {e}") from e

# Assume a standard signature length for the appended signature.
# For example, RSA-2048 with SHA-256 PSS padding typically results in a 256-byte signature.
SIGNATURE_LENGTH = 256

@shared_task
def import_partner_snapshot(
    snapshot_body: bytes,
) -> int:
    # CWE-353: Improper Handling of Incomplete Assurances
    # The original code directly parses `snapshot_body` without verifying its authenticity or integrity.
    # It assumes the `snapshot_body` is trustworthy, which is an incomplete assurance when dealing
    # with external partner data that is expected to be signed.
    # To fix this, we introduce signature verification using the partner's public key before processing.

    # 1. Ensure `snapshot_body` is long enough to contain both the actual data and the signature.
    if len(snapshot_body) <= SIGNATURE_LENGTH:
        raise ValueError("Invalid snapshot_body: too short to contain data and signature.")

    # 2. Split the `snapshot_body` into the actual data and the signature.
    # It is assumed here that the signature is appended to the data.
    data_to_verify = snapshot_body[:-SIGNATURE_LENGTH]
    signature = snapshot_body[-SIGNATURE_LENGTH:]

    # 3. Verify the signature using the pre-loaded partner's public key.
    try:
        _partner_public_key.verify(
            signature,
            data_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        # If verification fails, it indicates that the snapshot is either tampered with or
        # originates from an unauthentic source. We must not process untrusted data.
        raise ValueError(f"Signature verification failed: {e}") from e

    # 4. If verification passes, proceed with parsing the VERIFIED and authenticated data.
    # The `parse_partner_snapshot` function now receives only the legitimate payload.
    records = parse_partner_snapshot(
        data_to_verify
    )

    for record in records:
        partner_repository.save(
            record
        )

    return len(
        records
    )
