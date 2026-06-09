import logging

from fastapi import FastAPI, Header

app = FastAPI()
logger = logging.getLogger(
    "gateway"
)


# The original code calls load_account().
# This definition is added to ensure the code is syntactically complete as per rules.
def load_account() -> dict:
    # In a real application, this function would load actual account data.
    # For this exercise, it's a minimal placeholder.
    return {"user_id": "example_user", "account_balance": 1000}


@app.get("/api/account")
async def account(
    authorization: str = Header(
        alias="Authorization",
    ),
) -> dict:
    # CWE-532 fix: Prevent sensitive authorization token from being logged directly.
    # The authorization header often contains sensitive credentials (e.g., Bearer tokens).
    # Logging its full value directly is a security risk.
    # Replace the actual sensitive value with a masked string in the log.
    logger.info(
        "authorization=%s",
        "********",  # Sensitive authorization token is masked
    )

    return load_account()
