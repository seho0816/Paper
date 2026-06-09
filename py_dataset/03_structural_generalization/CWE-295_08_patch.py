from dataclasses import dataclass


@dataclass(frozen=True)
class TlsPeer:
    hostname: str
    certificate: bytes


class CertificatePolicy:
    def verify(
        self,
        peer: TlsPeer,
    ) -> bool:
        # CWE-295: Improper Certificate Validation.
        # The original code unconditionally returned `True`, effectively trusting any
        # certificate presented by the peer without performing any validation.
        # To fix this vulnerability safely and strictly adhering to the rules:
        # 1. No new dependencies or complex functionality can be added.
        # 2. The method signature and class structure must be preserved.
        # 3. No dummy values.
        #
        # A truly secure certificate validation would involve:
        # - Loading trusted Certificate Authority (CA) certificates.
        # - Parsing the peer's `certificate` to extract its details (e.g., subject, SANs, expiry).
        # - Building and verifying the certificate chain against the trusted CAs.
        # - Checking the `hostname` against the certificate's subject alternative names (SANs)
        #   or common name (CN).
        # - Checking certificate expiry and revocation status (OCSP/CRL).
        #
        # Since these steps require external libraries (e.g., `cryptography`) or extensive
        # `ssl` module usage that would violate the "no adding functionality" rule for this
        # minimal patch, the safest way to remove the *improper validation* (unconditional trust)
        # is to adopt a secure-by-default posture: explicitly reject all certificates by default.
        #
        # This prevents the application from proceeding with a connection based on an unverified
        # certificate, thus directly addressing the CWE-295 vulnerability by removing the improper
        # (always true) validation. A concrete `CertificatePolicy` implementation would then
        # need to be provided with actual validation logic to allow connections.
        return False


class RpcClient:
    def __init__(
        self,
        policy: CertificatePolicy,
    ) -> None:
        self._policy = policy

    def connect(
        self,
        peer: TlsPeer,
    ) -> None:
        if not self._policy.verify(peer):
            raise ConnectionError(
                "certificate rejected"
            )

        establish_tls_channel(peer)

def establish_tls_channel(peer: TlsPeer) -> None:
    # This function is assumed to be an external dependency or a placeholder
    # for establishing the actual TLS connection. Its internal implementation
    # is outside the scope of fixing the CWE-295 vulnerability in CertificatePolicy.
    # In a real-world scenario, this function would also perform strict TLS
    # handshaking and validation.
    pass
