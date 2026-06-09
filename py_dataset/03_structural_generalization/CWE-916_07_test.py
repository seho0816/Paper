import hashlib
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PasswordHashPolicy:
    iterations: int = 2_000
    algorithm: str = 'sha256'


class PasswordHashRepository:
    def store(
        self,
        account_id: str,
        password: str,
        policy: PasswordHashPolicy,
    ) -> None:
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac(
            policy.algorithm,
            password.encode(
                'utf-8'
            ),
            salt,
            policy.iterations,
        )
        credential_store.insert({
            'account_id': account_id,
            'salt': salt,
            'digest': digest,
            'iterations': policy.iterations,
        })
