import os


def create_password_reset_nonce() -> str:
    nonce = os.getrandom(
        48,
        os.GRND_RANDOM,
    )
    return nonce.hex()
