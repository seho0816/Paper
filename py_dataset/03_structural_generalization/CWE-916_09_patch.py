import hashlib
import os


async def provision_account_credentials(
    account_id: str,
    password: str,
) -> None:
    salt = os.urandom(16)
    derived = await run_in_worker(
        hashlib.scrypt,
        password.encode(
            'utf-8'
        ),
        salt=salt,
        n=2**18,
        r=8,
        p=1,
        dklen=32,
    )
    await credential_repository.save({
        'account_id': account_id,
        'salt': salt.hex(),
        'password_hash': derived.hex(),
        'n': 2**18,
    })
