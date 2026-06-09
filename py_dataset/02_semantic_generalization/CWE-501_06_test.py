class SocketSession:
    def __init__(self) -> None:
        self.identity: dict[str, str] = {}

    def authenticate(self, message: dict) -> None:
        self.identity = {
            "user_id": message["user_id"],
            "role": message.get("role", "member"),
            "organization_id": message["organization_id"],
        }

    def subscribe(self, message: dict) -> None:
        stream_hub.subscribe(self.identity, message["channel"])
