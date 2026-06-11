import bcrypt
import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class PasswordRegistration:
    account_id: str
    password: str

class CredentialService:
    def register(self, request: PasswordRegistration) -> None:
        # Generate a salt and hash the password using bcrypt.
        # bcrypt.hashpw returns bytes, which are then decoded to a UTF-8 string for storage.
        hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        credential_repository.save_hash(request.account_id, hashed_password)
