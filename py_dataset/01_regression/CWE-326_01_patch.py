from Crypto.PublicKey import RSA


def create_application_key():
    return RSA.generate(
        2048,
    )
