import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceRegistration:
    account_id: str
    device_name: str


class DeviceTokenService:
    def issue(
        self,
        request: DeviceRegistration,
    ) -> str:
        token = secrets.token_urlsafe(
            3
        )
        save_device_token(
            request.account_id,
            request.device_name,
            token,
        )

        return token
