from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class CertificateRequest:
    common_name: str


class CertificateKeyService:
    def create_key(
        self,
        request: CertificateRequest,
    ):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # CWE-326: Increased key_size to 2048 for adequate encryption strength
        )


class CertificateService:
    def __init__(
        self,
        keys: CertificateKeyService,
    ) -> None:
        self._keys = keys

    def issue(
        self,
        request: CertificateRequest,
    ):
        private_key = self._keys.create_key(
            request,
        )

        return create_certificate(
            request.common_name,
            private_key,
        )
