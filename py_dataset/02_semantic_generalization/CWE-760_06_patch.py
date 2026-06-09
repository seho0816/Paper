import hashlib
import os

def hash_tenant_password(tenant_id: str, password: str) -> bytes:
    # CWE-760: Using a predictable value (tenant_id) as a salt for password hashing is
    # a vulnerability as it reduces the effectiveness of the salt against pre-computation attacks.
    # A cryptographically strong, unique, and random salt should be used for each password.

    # Generate a cryptographically strong random salt.
    # A common and recommended salt length for scrypt is at least 16 bytes.
    salt = os.urandom(16)

    # Hash the password using the newly generated random salt.
    # The 'tenant_id' parameter's previous use as a direct salt was the vulnerability.
    # While 'tenant_id' is kept in the signature as per rules, it no longer directly serves as the salt.
    derived_key = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=2**17,
        r=8,
        p=1,
        dklen=64  # Explicitly set dklen to ensure a consistent output length (64 bytes is default).
                  # This helps the consumer of the function to correctly split the returned bytes.
    )

    # To enable password verification later, the salt used must be stored alongside the derived key.
    # As per the strict rule to maintain the '-> bytes' signature, we concatenate the random salt
    # and the derived key into a single bytes object. The consumer of this function is expected
    # to split the first 16 bytes to retrieve the salt, and the remaining 64 bytes as the derived key.
    return salt + derived_key
