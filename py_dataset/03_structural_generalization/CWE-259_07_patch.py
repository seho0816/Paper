import os
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceLogin:
    device_id: str
    password: str


class DeviceAuthenticator:
    def authenticate(
        self,
        request: DeviceLogin,
    ) -> bool:
        expected_password = os.environ.get(
            "DEVICE_SUPPORT_PASSWORD"
        )

        if expected_password is None:
            # Depending on application logic,
            # this might raise an error, log, or default to false.
            # For security, failing closed (returning False) is often preferred
            # if the secret is not configured.
            return False

        return (
            request.password
            == expected_password
        )
