import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class PasswordRegistration:
    account_id: str
    password: str

class CredentialService:
    def register(self, request: PasswordRegistration) -> None:
        digest = hashlib.sha256(request.password.encode('utf-8')).hexdigest()
        credential_repository.save_hash(request.account_id, digest)
