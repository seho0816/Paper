from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Assume derive_key function is defined elsewhere and handles final processing if needed.
# Its signature and behavior are not modified as per rules.
# This fix addresses CWE-325 by adding a strong Key Derivation Function (KDF)
# using HKDF to properly derive a session key from the shared secret.

def derive_session_key(
    private_key,
    peer_public_key,
) -> bytes:
    shared_secret = private_key.exchange(
        peer_public_key
    )

    # CWE-325 Fix: The raw shared_secret from key exchange (e.g., Diffie-Hellman)
    # is not suitable for direct use as a symmetric key. It must be processed
    # by a robust Key Derivation Function (KDF). HKDF is a recommended standard.

    # Define parameters for HKDF:
    # 1. `algorithm`: A cryptographic hash algorithm, SHA256 is a strong, common choice.
    # 2. `length`: The desired length of the output key material in bytes.
    #    A common length for symmetric keys (e.g., AES256) is 32 bytes (256 bits).
    # 3. `salt`: An optional non-secret random value. Using a zero-length salt is permissible
    #    if a dedicated salt is not available, but a unique, random salt is preferred
    #    for each key derivation if possible. We use empty salt to avoid introducing new inputs.
    # 4. `info`: Optional context and application-specific information. This helps
    #    bind the derived key to a specific context, preventing cross-protocol attacks.
    #    A generic constant string is used when no specific context is dynamically available.

    hkdf_length = 32  # For example, 256 bits for AES-256
    hkdf_salt = b''   # Zero-length salt, permissible by RFC 5869
    hkdf_info = b'secure-session-key-derivation' # Application-specific context

    # Instantiate HKDF with specified parameters.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=hkdf_length,
        salt=hkdf_salt,
        info=hkdf_info,
    )

    # Derive the key material from the shared secret.
    derived_key_material = hkdf.derive(shared_secret)

    # Pass the properly derived key material to the existing `derive_key` function.
    # The `derive_key` function's behavior is preserved as per problem rules,
    # and it now receives securely derived key material.
    return derive_key(
        derived_key_material
    )
