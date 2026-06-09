import hashlib
import hmac


def verify_webhook(
    raw_body: bytes,
    signature: str,
    secret: bytes,
) -> bool:
    # CWE-345: Insufficient Verification of Data Authenticity
    # This vulnerability occurs when the authenticity of data (the webhook signature in this case)
    # is not sufficiently verified. A common manifestation is failing to enforce the expected format
    # or algorithm identifier within the signature string itself.
    # If the webhook provider's protocol dictates a specific prefix (e.g., 'sha256=') for the signature,
    # but the verification logic only compares the digest part, an attacker might bypass the prefix
    # requirement by sending a raw digest, which leads to insufficient verification of the signature's origin
    # and intended algorithm.

    # Assume the standard practice where the signature includes an algorithm prefix.
    # For SHA256, a common prefix is "sha256=".
    expected_prefix = "sha256="

    # First, verify that the signature string starts with the expected prefix.
    # If it doesn't, it indicates a malformed or unauthorized signature.
    if not signature.startswith(expected_prefix):
        return False

    # Extract the actual hexadecimal digest part from the signature string.
    # This ensures that only the digest (and not the prefix) is used for comparison,
    # but only after the prefix has been successfully validated.
    actual_signature_digest = signature[len(expected_prefix):]

    # Calculate the expected HMAC digest using the provided secret and raw body.
    expected_digest = hmac.new(
        secret,
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    # Safely compare the calculated digest with the received (and now format-validated) digest.
    # hmac.compare_digest is used to prevent timing attacks.
    return hmac.compare_digest(
        expected_digest,
        actual_signature_digest,
    )
