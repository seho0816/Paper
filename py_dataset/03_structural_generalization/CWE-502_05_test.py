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
        self._upload_root = upload_root

    def load(
        self,
        request: ModelActivationRequest,
    ) -> object:
        artifact_path = (
            self._upload_root
            / request.upload_name
        )

        return joblib.load(
            artifact_path,
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
