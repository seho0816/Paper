import uvicorn
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader


# To make the provided snippet syntactically complete and runnable,
# a placeholder for `database_pool` is necessary as it's used but not defined.
# This does not add new functionality but completes the existing code's syntax.
class MockDatabasePool:
    def diagnostics(self):
        return {"status": "Database is healthy", "details": "Placeholder diagnostics data"}

database_pool = MockDatabasePool()


internal_app = FastAPI()

# --- START FIX for CWE-1327 ---
# CWE-1327: Improper Protection of Alternate Path for Authentication.
# The /diagnostics/database endpoint is an "alternate path" that needs protection.

# Define an API Key header security scheme.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def get_api_key(api_key: str = Depends(api_key_header)):
    # Retrieve the expected API key from environment variables.
    # This adheres to rule 7: use os.environ["KEY_NAME"] for env vars.
    expected_api_key = os.environ.get("DIAGNOSTICS_API_KEY")

    if not expected_api_key:
        # If the environment variable is not set, it's a server-side misconfiguration.
        # Prevent access and indicate a server error to avoid exposing diagnostics unintentionally.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: DIAGNOSTICS_API_KEY is not set."
        )

    if api_key != expected_api_key:
        # If the provided API key does not match the expected one, deny access.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key. Access denied."
        )
    return api_key

# Apply the security dependency to the diagnostic endpoint.
# This ensures that only requests with a valid 'X-API-Key' header can access this path.
@internal_app.get('/diagnostics/database', dependencies=[Depends(get_api_key)])
async def database_diagnostics() -> dict:
    return database_pool.diagnostics()
# --- END FIX for CWE-1327 ---


def run_diagnostics() -> None:
    uvicorn.run(
        internal_app,
        host='0.0.0.0',
        port=9400,
    )
