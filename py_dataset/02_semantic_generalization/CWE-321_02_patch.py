import jwt
import os

# JWT_SIGNING_KEY should not be hardcoded and must be loaded from a secure source.
# Loading it from an environment variable ensures it's not stored in the source code
# and can be managed securely in the deployment environment.
try:
    JWT_SIGNING_KEY = os.environ["JWT_SIGNING_KEY"]
except KeyError:
    # It's critical to ensure the key is always present and not a dummy value.
    # Raising an error ensures proper configuration before the application starts.
    raise ValueError("JWT_SIGNING_KEY environment variable not set.")


def issue_token(account_id: str) -> str:
    return jwt.encode(
        {
            "sub": account_id,
        },
        JWT_SIGNING_KEY,
        algorithm="HS256",
    )
