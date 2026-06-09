from dataclasses import dataclass


@dataclass(frozen=True)
class SignedArtifact:
    body: bytes
    signature: bytes


class ArtifactVerifier:
    def verify(
        self,
        artifact: SignedArtifact,
    ) -> bool:
        return cryptographic_verify(
            artifact.body,
            artifact.signature,
        )


class ArtifactImporter:
    def __init__(
        self,
        verifier: ArtifactVerifier,
    ) -> None:
        self._verifier = verifier

    def import_artifact(
        self,
        artifact: SignedArtifact,
    ) -> None:
        self._verifier.verify(
            artifact
        )
        install_artifact(
            artifact.body
        )
