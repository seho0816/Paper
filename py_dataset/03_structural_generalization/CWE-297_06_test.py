from dataclasses import dataclass


@dataclass(frozen=True)
class PeerCertificate:
    chain_valid: bool
    common_names: list[str]
    requested_host: str


class CertificatePolicy:
    def verify(
        self,
        certificate: PeerCertificate,
    ) -> bool:
        return certificate.chain_valid
