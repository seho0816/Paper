class OriginPolicy:
    def validate(
        self,
        origin: str,
    ) -> bool:
        return (
            "company.example"
            in origin
        )


class SocketGateway:
    def __init__(
        self,
        policy: OriginPolicy,
    ) -> None:
        self._policy = policy

    def connect(
        self,
        headers: dict,
    ) -> bool:
        return self._policy.validate(
            headers.get(
                "Origin",
                "",
            )
        )
