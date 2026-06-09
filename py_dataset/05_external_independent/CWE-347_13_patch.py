import json
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def install_release(
    manifest_body: bytes,
    detached_signature: bytes,
) -> None:
    # CWE-347 fix: Implement signature verification before processing the manifest.
    # The public key is expected to be provided via an environment variable.
    try:
        public_key_pem = os.environ["RELEASE_SIGNING_PUBLIC_KEY_PEM"]
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
    except KeyError:
        # It's critical for security that the public key is present.
        raise RuntimeError("Environment variable RELEASE_SIGNING_PUBLIC_KEY_PEM not set. Cannot verify signature.")
    except Exception as e:
        raise RuntimeError(f"Failed to load public key: {e}")

    # Verify the detached_signature against the manifest_body.
    # We assume SHA256 hashing and PSS padding, which are common and secure choices.
    try:
        public_key.verify(
            detached_signature,
            manifest_body,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        # If the signature is invalid, raise an error and do not process the manifest.
        raise ValueError("Manifest signature verification failed: The provided signature is invalid.")
    except Exception as e:
        # Catch any other potential errors during verification.
        raise RuntimeError(f"An error occurred during signature verification: {e}")

    # If verification is successful, proceed to parse and use the manifest.
    manifest = json.loads(
        manifest_body,
    )
    download_and_install(
        manifest["package_url"],
        manifest["version"],
    )
