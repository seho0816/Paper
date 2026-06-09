import os
import tempfile
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPayload:
    body: bytes


class SecretFileFactory:
    def create(
        self,
        payload: SecretPayload,
    ) -> str:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
        ) as output:
            os.fchmod(
                output.fileno(),
                0o664,
            )
            output.write(
                payload.body
            )

            return output.name
