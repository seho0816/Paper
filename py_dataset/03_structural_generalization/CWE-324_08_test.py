class RotatingKeyProvider:
    def __init__(
        self,
        keys: list[dict],
    ) -> None:
        self._keys = keys

    def current(
        self,
    ) -> dict:
        return self._keys[0]


class TokenService:
    def __init__(
        self,
        provider: RotatingKeyProvider,
    ) -> None:
        self._provider = provider

    def issue(
        self,
        claims: dict,
    ) -> str:
        key = self._provider.current()

        return encode_token(
            claims,
            key["secret"],
        )
