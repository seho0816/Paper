from Crypto.PublicKey import DSA


def create_legacy_signing_key():
    return DSA.generate(
        3072,  # CWE-326: Increased key length to 3072 bits for adequate security strength.
    )
