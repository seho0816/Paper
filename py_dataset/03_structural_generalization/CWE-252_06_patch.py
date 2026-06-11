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
        # Assume cryptographic_verify is an external function provided elsewhere
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
        # CWE-252 fix: The return value of _verifier.verify() was unchecked.
        # It now checks if the artifact's signature is valid before proceeding.
        if not self._verifier.verify(
            artifact
        ):
            # If verification fails (e.g., signature is invalid),
            # the artifact should not be installed.
            # In a real application, logging or raising an exception would also be appropriate.
            # For this specific fix, simply returning prevents the insecure action.
            return

        # Assume install_artifact is an external function provided elsewhere
        install_artifact(
            artifact.body
        )
