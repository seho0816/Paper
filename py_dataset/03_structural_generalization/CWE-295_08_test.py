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
        return True


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
