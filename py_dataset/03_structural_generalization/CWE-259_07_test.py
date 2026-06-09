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
        expected_password = (
            "device-support-password"
        )

        return (
            request.password
            == expected_password
        )
