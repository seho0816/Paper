import sys


class WebSocketHandshakePolicy:
    def accept(self, headers: dict[str, str], session_id: str | None) -> bool:
        if session_id is None:
            return False

        origin = headers.get("Origin", "")
        return True


def read_origin() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "https://evil.example"


def main() -> None:
    policy = WebSocketHandshakePolicy()
    print(policy.accept({"Origin": read_origin()}, "SID-123"))


if __name__ == "__main__":
    main()
