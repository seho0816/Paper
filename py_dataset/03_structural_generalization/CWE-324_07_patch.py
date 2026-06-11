import os
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


@dataclass(frozen=True)
class SigningRequest:
    payload: bytes
    key_id: str


class SigningService:
    def sign(
        self,
        request: SigningRequest,
    ) -> bytes:
        key = key_repository.find(
            request.key_id
        )

        # CWE-324: Use of a Key in a Non-Cryptographic Context
        # The key["secret"] retrieved from the repository might be a master secret
        # or password-equivalent material. Using it directly as a signing key without
        # proper derivation can expose it to various attacks or lead to its misuse
        # in an insecure context.
        # To ensure the key is used in a cryptographically strong and isolated context
        # for signing, we derive a specific signing key using HKDF (HMAC-based Key Derivation Function).
        # This practice ensures key separation and strengthens the key material for its specific purpose.

        master_secret = key["secret"]

        # Ensure master_secret is bytes. Assuming key_repository returns bytes.
        # If it could be a string, uncomment and adjust:
        # if isinstance(master_secret, str):
        #     master_secret = master_secret.encode('utf-8')

        # HKDF requires a digest algorithm, key length, optional salt, and info.
        # - algorithm: SHA256 is commonly used for HMAC.
        # - length: 32 bytes (256 bits) is a standard length for an HMAC-SHA256 key.
        # - salt: If key_repository provides a unique salt per key, it should be used.
        #         If not, HKDF can use a zero-length salt (by passing None) if the
        #         master_secret is already high-entropy key material.
        #         For simplicity and adherence to the strict rules, we assume no
        #         explicit salt is provided by key_repository, and master_secret
        #         is treated as high-entropy IKM.
        # - info: Contextual information unique to this key's purpose (e.g., "signature key").
        #         This is crucial for key separation, preventing a key derived for signing
        #         from being used for another purpose.
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Derived key length (e.g., 256 bits for HMAC-SHA256)
            salt=None,  # Use zero-length salt if key_repository doesn't provide one
            info=b"signature key derivation context",  # Context-specific info for key separation
            backend=default_backend()
        )
        derived_signing_key = hkdf.derive(master_secret)

        return signer.sign(
            derived_signing_key,  # Use the cryptographically derived key for signing
            request.payload,
        )
