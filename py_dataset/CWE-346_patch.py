import sys


class WebSocketHandshakePolicy:
    def __init__(self, allowed_origins: list[str]):
        self.allowed_origins = allowed_origins

    def accept(self, headers: dict[str, str], session_id: str | None) -> bool:
        if session_id is None:
            return False

        origin = headers.get("Origin")

        if origin is None or origin not in self.allowed_origins:
            return False

        return True


def read_origin() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "https://evil.example"


def main() -> None:
    trusted_origins = ["https://trusted.example", "https://another.trusted.domain"]
    policy = WebSocketHandshakePolicy(trusted_origins)
    print(policy.accept({"Origin": read_origin()}, "SID-123"))


if __name__ == "__main__":
    main()
