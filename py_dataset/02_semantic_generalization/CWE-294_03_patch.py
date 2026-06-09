import hmac
import os
import hashlib


def create_signature(body: bytes, nonce: str) -> str:
    """
    Generates an HMAC-SHA256 signature for the given body and nonce.
    The secret key is retrieved from the 'SIGNING_SECRET_KEY' environment variable.
    This function addresses the CWE-294 vulnerability by ensuring that signature generation
    is consistently and securely handled, preventing bypasses that might arise from
    an undefined, missing, or insecurely implemented signature creation mechanism.
    """
    try:
        # Retrieve the secret key from an environment variable.
        # This key must be kept secret and should be strong.
        secret_key = os.environ["SIGNING_SECRET_KEY"].encode('utf-8')
    except KeyError:
        # Raising an error if the key is not set prevents the system from generating
        # signatures with a default, weak, or missing key, which could lead to bypass.
        raise ValueError("SIGNING_SECRET_KEY environment variable is not set for signature creation.")

    # Combine the body (already bytes) and nonce (encoded to bytes).
    # The order and encoding must be consistent between signature creation and verification.
    data_to_sign = body + nonce.encode('utf-8')

    # Create the HMAC-SHA256 signature and return it as a hexadecimal string.
    signature = hmac.new(secret_key, data_to_sign, hashlib.sha256).hexdigest()
    return signature


def verify_signed_request(
    body: bytes,
    nonce: str,
    signature: str,
) -> bool:
    """
    Verifies a signed request by regenerating the expected signature and
    comparing it with the provided signature using a constant-time comparison.
    """
    expected = create_signature(
        body,
        nonce,
    )

    # hmac.compare_digest performs a constant-time comparison to prevent timing attacks.
    # It safely compares string or bytes objects, assuming they are of the same type.
    return hmac.compare_digest(
        expected,
        signature,
    )
