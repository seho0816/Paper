import time


class ResetContextCache:
    def __init__(self) -> None:
        self.cache: dict[str, dict[str, object]] = {}

    def remember(self, user_id: str, email: str, token: str) -> None:
        self.cache[user_id] = {
            "email": email,
            "token": token,
            "created_at": time.time(),
        }

    def get(self, user_id: str) -> dict[str, object]:
        return self.cache[user_id]


def main() -> None:
    cache = ResetContextCache()
    cache.remember("user-100", "mube@example.com", "RESET-TOKEN-ABC")
    print(cache.get("user-100"))


if __name__ == "__main__":
    main()
