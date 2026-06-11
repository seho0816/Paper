import os
from dataclasses import dataclass
from pathlib import Path

import joblib


@dataclass(frozen=True)
class ModelActivationRequest:
    upload_name: str


class ModelArtifactRepository:
    def __init__(
        self,
        upload_root: Path,
    ) -> None:
        # Resolve the upload_root once to get its canonical, absolute path.
        # This helps in robust path comparisons later.
        self._upload_root = upload_root.resolve()

    def load(
        self,
        request: ModelActivationRequest,
    ) -> object:
        # CWE-502: Deserialization of Untrusted Data.
        # The primary vulnerability here is that `joblib.load` can execute arbitrary
        # code if the file content is malicious. If `artifact_path` can be manipulated
        # by an attacker, they could force the application to deserialize a malicious file.

        # Mitigation steps:
        # 1. Sanitize the user-provided `upload_name` to prevent path traversal (CWE-22).
        #    Extracting only the filename component ensures that no directory separators
        #    (like '..' or '/') can alter the intended directory.
        safe_upload_filename = Path(request.upload_name).name

        # 2. Construct the full path to the candidate artifact using the sanitized filename.
        candidate_artifact_path = self._upload_root / safe_upload_filename

        # 3. Perform strict validation on the `candidate_artifact_path`:
        #    a. Ensure the file actually exists and is a regular file (not a directory, symlink etc.).
        if not candidate_artifact_path.is_file():
            raise FileNotFoundError(f"Model artifact not found: {candidate_artifact_path}")

        #    b. Resolve the path to its canonical form. This is crucial to detect and prevent
        #       symlink attacks where a seemingly safe filename might resolve to a path
        #       outside the intended `_upload_root`.
        resolved_artifact_path = candidate_artifact_path.resolve()

        #    c. Verify that the `resolved_artifact_path` is strictly contained within
        #       the designated `_upload_root`. This is the core defense against loading
        #       files from unauthorized locations, even if path traversal was attempted
        #       via symlinks or other file system trickery.
        #       Path.is_relative_to() (Python 3.9+) is the most robust way to do this.
        if not resolved_artifact_path.is_relative_to(self._upload_root):
            # If for some reason resolved_artifact_path is outside the root (e.g., symlink attack)
            raise ValueError(f"Attempted to access an unauthorized model artifact path: {candidate_artifact_path}")

        # At this point, `resolved_artifact_path` is guaranteed to point to a regular file
        # that is strictly located within the `_upload_root` directory.
        # The remaining CWE-502 risk would be if *malicious joblib files* can be placed
        # directly into `_upload_root` (e.g., during an upload process not covered by this code)
        # and then subsequently loaded. Addressing that specific scenario usually requires
        # out-of-band file content validation or a custom deserializer (which would
        # fundamentally change the use of `joblib.load` and violate "maintain structure").
        # Given the constraints, ensuring the file's location is trusted is the most direct
        # and compliant fix for this component.

        return joblib.load(
            resolved_artifact_path,
        )


class ModelActivationService:
    def __init__(
        self,
        repository: ModelArtifactRepository,
    ) -> None:
        self._repository = repository

    def activate(
        self,
        payload: dict,
    ) -> object:
        request = ModelActivationRequest(
            upload_name=str(
                payload["upload_name"],
            ),
        )

        return self._repository.load(
            request,
        )
