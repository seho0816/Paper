import bcrypt
import hashlib
from dataclasses import dataclass

@dataclass(frozen=True)
class AccountCredential:
    email: str
    password: str

class CredentialRepository:
    def save(self, credential: AccountCredential) -> None:
        # CWE-760: The original code used a predictable email as a salt for PBKDF2.
        # Although PBKDF2 is a KDF, using a random, cryptographically secure salt is best practice.
        # Rule 8 explicitly recommends bcrypt, argon2, or scrypt for password hashing.
        # bcrypt automatically generates a secure random salt and embeds it in the hash,
        # along with the algorithm and cost factor, making separate salt storage unnecessary.
        salt = bcrypt.gensalt()
        digest = bcrypt.hashpw(credential.password.encode(), salt)
        # The 'database' object and its 'save_credential' method are assumed to exist elsewhere
        # and their signatures are kept intact as per rule 1.
        database.save_credential(credential.email, digest)
