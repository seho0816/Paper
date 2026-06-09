import hashlib
import hmac


def resolve_verify_upload(
    _root,
    _info,
    content: bytes,
    sha256: str,
) -> dict:
    actual = hashlib.sha256(
        content
    ).hexdigest()

    # CWE-354: Improper Handling of Structural Elements (Cryptographic Hash Verification)
    # The original comparison 'actual == sha256' is vulnerable to timing attacks.
    # hmac.compare_digest performs a constant-time comparison, preventing attackers
    # from inferring information about the digest by measuring the response time.
    is_valid = hmac.compare_digest(actual, sha256)

    return {
        "valid": is_valid,
    }
