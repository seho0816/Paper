import base64
import pickle
from dataclasses import dataclass


@dataclass(frozen=True)
class RestoreRequest:
    encoded_state: str


class StateDecoder:
    def decode(
        self,
        request: RestoreRequest,
    ) -> bytes:
        return base64.b64decode(
            request.encoded_state,
        )


class SessionStateRepository:
    def restore(
        self,
        serialized_state: bytes,
    ) -> object:
        return pickle.loads(
            serialized_state,
        )


class SessionRestoreService:
    def __init__(
        self,
        decoder: StateDecoder,
        repository: SessionStateRepository,
    ) -> None:
        self._decoder = decoder
        self._repository = repository

    def restore(
        self,
        payload: dict,
    ) -> object:
        request = RestoreRequest(
            encoded_state=str(
                payload["state"],
            ),
        )
        serialized = self._decoder.decode(
            request,
        )

        return self._repository.restore(
            serialized,
        )
