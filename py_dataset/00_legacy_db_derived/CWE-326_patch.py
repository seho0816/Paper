from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class KeyIssuer:
    def create_private_key(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # CWE-326: Increased key size to a secure minimum (2048 bits)
        )

    def export_public_key(self) -> bytes:
        key = self.create_private_key()
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def main() -> None:
    issuer = KeyIssuer()
    print(issuer.export_public_key().decode("utf-8")[:80])


if __name__ == "__main__":
    main()
