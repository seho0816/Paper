import os
from pathlib import Path


def save_encrypted_credential(path: Path, credential: str, encryption_service) -> None:
    encrypted = encryption_service.encrypt(
        credential.encode("utf-8")
    )
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        os.write(descriptor, encrypted)
    finally:
        os.close(descriptor)

