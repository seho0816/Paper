from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
import os

app = FastAPI()

# Define an API key header for authentication
api_key_header = APIKeyHeader(name="X-Admin-API-Key", auto_error=True)

# Dependency to validate the admin API key
async def get_admin_api_key(api_key: str = Depends(api_key_header)):
    # Retrieve the expected API key from environment variables.
    # This prevents hardcoding secrets and adheres to the rule of using os.environ.
    expected_api_key = os.environ.get("ADMIN_API_KEY")

    if not expected_api_key:
        # If the ADMIN_API_KEY environment variable is not set,
        # it indicates a server misconfiguration, and access to critical functions
        # should be prevented.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin API key is not configured on the server."
        )

    # Compare the API key provided in the request with the expected key.
    if api_key != expected_api_key:
        # If the keys do not match, raise an HTTPException for unauthorized access.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Admin-API-Key."
        )
    # If authentication is successful, return the key or a user object.
    return api_key


@app.post("/api/admin/accounts/{account_id}/unlock", dependencies=[Depends(get_admin_api_key)])
async def unlock_account(
    account_id: str,
) -> dict:
    # The 'clear_account_lock' function is assumed to be defined elsewhere
    # as it was not provided in the original vulnerable snippet.
    clear_account_lock(
        account_id,
    )

    return {
        "unlocked": True,
    }
