import base64
import pickle
from dataclasses import dataclass
import io
import sys


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
        class SafeUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                # Restrict deserialization to safe, built-in types to prevent arbitrary code execution
                # associated with CWE-502 (Deserialization of Untrusted Data).
                # Only allows basic data structures and primitives.
                if module == "builtins" and name in (
                    "dict", "list", "tuple", "set", "str", "bytes", "int", "float",
                    "bool", "NoneType",
                ):
                    return getattr(sys.modules[module], name)
                
                # Forbid any other classes from being unpickled.
                raise pickle.UnpicklingError(f"Attempted to unpickle forbidden class {module}.{name}")

        return SafeUnpickler(io.BytesIO(serialized_state)).load()


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
