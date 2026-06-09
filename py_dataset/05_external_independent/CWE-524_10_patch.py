from flask_caching import Cache
import bcrypt


cache = Cache()


def cache_reset_request(email: str, token: str) -> None:
    # Hash the token before storing it to prevent information exposure (CWE-524).
    # Use bcrypt for strong, slow hashing suitable for sensitive tokens.
    hashed_token = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    cache.set(
        "reset:" + email,
        {
            "email": email,
            "token": hashed_token,
        },
        timeout=600,
    )
