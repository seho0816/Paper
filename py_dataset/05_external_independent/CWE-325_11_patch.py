import hmac
import hashlib

def decode_encrypted_token(
    encrypted_payload: bytes,
    token_signature: bytes,
    key: bytes,
) -> dict:
    # CWE-325 fix: The 'token_signature' parameter was present but not used,
    # leading to a missing cryptographic integrity check.
    # This patch adds verification of the token_signature against the
    # encrypted_payload using HMAC-SHA256, ensuring the token's integrity
    # and authenticity before decryption.
    
    # Calculate the expected signature using the key and the encrypted payload.
    expected_signature = hmac.new(key, encrypted_payload, hashlib.sha256).digest()

    # Compare the provided token_signature with the expected signature
    # in a timing-attack safe manner.
    if not hmac.compare_digest(expected_signature, token_signature):
        raise ValueError("Invalid token signature")

    plaintext = decrypt_token(
        encrypted_payload,
        key,
    )

    return parse_claims(
        plaintext
    )
