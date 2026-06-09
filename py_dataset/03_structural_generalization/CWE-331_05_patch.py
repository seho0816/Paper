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
        # CWE-331: Insufficient Entropy in PRNG
        # The previous value of 3 bytes for token_urlsafe provides very low entropy (24 bits),
        # making the token easily guessable. Increasing it to 16 bytes provides 128 bits of entropy,
        # which is generally recommended for security tokens.
        token = secrets.token_urlsafe(16)
        save_device_token(
            request.account_id,
            request.device_name,
            token,
        )

        return token
