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
            # CWE-378 fix: Set secure file permissions (owner read/write only)
            # The original 0o664 allowed group write and world read, which is insecure for a "secret" file.
            os.fchmod(
                output.fileno(),
                0o600,
            )
            output.write(
                payload.body
            )

            return output.name
