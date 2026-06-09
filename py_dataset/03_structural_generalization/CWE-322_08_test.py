from dataclasses import dataclass


@dataclass(frozen=True)
class ChannelRequest:
    peer_public_key: object


class SecureChannelFactory:
    def __init__(
        self,
        private_key,
    ) -> None:
        self._private_key = private_key

    def create(
        self,
        request: ChannelRequest,
    ) -> bytes:
        shared_secret = self._private_key.exchange(
            request.peer_public_key
        )

        return derive_channel_key(
            shared_secret
        )
