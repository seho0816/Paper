from Crypto.PublicKey import DSA


def create_legacy_signing_key():
    return DSA.generate(
        1024,
    )
