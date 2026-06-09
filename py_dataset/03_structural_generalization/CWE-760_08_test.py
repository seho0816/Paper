import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class AccountCredential:
    email: str
    password: str

class CredentialRepository:
    def save(self, credential: AccountCredential) -> None:
        digest = hashlib.pbkdf2_hmac(
            'sha256',
            credential.password.encode(),
            credential.email.lower().encode(),
            600_000,
        )
        database.save_credential(credential.email, digest)
