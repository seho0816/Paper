import os
from dataclasses import dataclass
from argon2 import low_level


@dataclass(frozen=True)
class PasswordHashPolicy:
    # CWE-916 fix: Update default password hashing parameters to secure values
    # The 'iterations' field is now mapped to Argon2's 'time_cost'.
    # A time_cost of 4 is a reasonable default for Argon2.
    iterations: int = 4
    # The 'algorithm' field now defaults to 'argon2id', as mandated by strict rule #8.
    algorithm: str = 'argon2id'


class PasswordHashRepository:
    def store(
        self,
        account_id: str,
        password: str,
        policy: PasswordHashPolicy,
    ) -> None:
        # CWE-916 fix: Replaced hashlib.pbkdf2_hmac with Argon2 (argon2id) for password hashing.
        # Argon2 is a modern, dedicated password hashing function that offers strong resistance
        # against brute-force and side-channel attacks through memory-hardness, time-hardness,
        # and parallelism. This change adheres to strict rule #8.

        # Generate a cryptographically secure random salt.
        salt = os.urandom(16)

        # Hash the password using Argon2id.
        # The policy.iterations parameter is used as the time_cost for Argon2.
        # Other Argon2 parameters (memory_cost, parallelism, hash_len) are set to strong defaults.
        digest = low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=policy.iterations,  # Map policy.iterations to Argon2's time_cost
            memory_cost=65536,            # 64 MB memory cost (in KiB)
            parallelism=4,                # 4 lanes (threads)
            hash_len=32,                  # 256-bit hash output length
            type=low_level.Type.ID,       # Use Argon2id variant
        )

        # The credential_store is assumed to be an existing object.
        # The structure of the dictionary passed to insert() is maintained.
        credential_store.insert({
            'account_id': account_id,
            'salt': salt,
            'digest': digest,
            'iterations': policy.iterations, # Store the Argon2 time_cost
        })
