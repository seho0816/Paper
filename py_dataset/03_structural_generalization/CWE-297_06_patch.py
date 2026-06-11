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
        # CWE-297: Improper Enforcement of a "Design by Contract" or "Data Structure" Invariant
        # The original code only checked chain_valid, but a complete certificate policy
        # should also verify that the requested host matches one of the common names
        # in the certificate to prevent hostname spoofing attacks.
        return certificate.chain_valid and certificate.requested_host in certificate.common_names
