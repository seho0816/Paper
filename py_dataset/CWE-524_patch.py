import time
import bcrypt


class ResetContextCache:
    def __init__(self) -> None:
        self.cache: dict[str, dict[str, object]] = {}

    def remember(self, user_id: str, email: str, token: str) -> None:
        # CWE-524 fix: Hash the sensitive token before storing it in the cache
        # to prevent information exposure if the cache is compromised.
        hashed_token = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.cache[user_id] = {
            "email": email,
            "token": hashed_token,  # Store the hashed token instead of the plain token
            "created_at": time.time(),
        }

    def get(self, user_id: str) -> dict[str, object]:
        # This method will now return the dictionary containing the hashed token,
        # thereby not exposing the original plain token.
        return self.cache[user_id]


def main() -> None:
    cache = ResetContextCache()
    cache.remember("user-100", "mube@example.com", "RESET-TOKEN-ABC")
    print(cache.get("user-100"))


if __name__ == "__main__":
    main()
