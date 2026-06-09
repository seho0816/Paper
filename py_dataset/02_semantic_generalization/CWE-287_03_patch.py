import os
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

# This function is not provided in the original snippet.
# As per strict rule #4, we must not add functions or rewrite the entire code.
# The original code calls `load_private_report()`, so we assume it exists elsewhere
# or is a placeholder for the actual business logic.
# We will not define it here.


@app.get("/api/private/report")
async def read_private_report(
    api_key: str | None = Header(
        default=None,
        alias="X-API-Key",
    ),
) -> dict:
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="API key required",
        )

    # CWE-287: Improper Authentication fix
    # Validate the provided API key against a securely stored secret key.
    # The secret API key should be loaded from environment variables
    # or a secure configuration system, not hardcoded.
    try:
        SECRET_API_KEY = os.environ["SECRET_API_KEY"]
    except KeyError:
        # If the environment variable is not set, it's a server configuration issue (500),
        # not an authentication failure (401) by the client.
        raise HTTPException(
            status_code=500,
            detail="Server configuration error: SECRET_API_KEY environment variable not set",
        )

    if api_key != SECRET_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
        )

    # Assume load_private_report() is defined elsewhere as per the original code's structure
    # and strict rule #4 (no new functions/rewrite).
    return {
        "report": load_private_report(),
    }
