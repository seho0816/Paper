from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)


def decrypt_record(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    # CWE-325 (Missing Protection of Multiple Scope Instances of a Sensitive Resource)
    # in the context of cryptographic operations often refers to the insecure handling
    # of sensitive data like cryptographic keys.
    # While `key` is an immutable `bytes` object and cannot be securely zeroed out
    # in-place using `cryptography.hazmat.primitives.util.secure_memzero` (which works
    # on mutable buffers like bytearrays), it is a best practice to remove the local
    # reference to sensitive data as soon as it's no longer strictly needed.
    # This helps to reduce its lifetime in the function's local scope, making it
    # eligible for garbage collection sooner and minimizing the window for potential
    # memory introspection attacks. The actual key material is copied by `algorithms.AES`
    # and managed by the `Cipher` object internally.
    decryptor = Cipher(
        algorithms.AES(
            key
        ),
        modes.CTR(
            nonce
        ),
    ).decryptor()

    # Clear the local reference to the sensitive key bytes immediately after it has
    # been used to initialize the cipher, minimizing its presence in the local scope.
    key = None

    return (
        decryptor.update(
            ciphertext
        )
        + decryptor.finalize()
    )
