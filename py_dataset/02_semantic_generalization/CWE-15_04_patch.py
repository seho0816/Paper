from fastapi import FastAPI

app = FastAPI()
FEATURE_FLAGS = {
    "allow_public_export": False,
    "skip_signature_check": False,
}

# Define a set of flags that are explicitly allowed to be updated via this API endpoint.
# This prevents external control over sensitive configuration items (CWE-15).
# By default, for security-critical flags like those in FEATURE_FLAGS,
# it's safest to assume they should not be modifiable via a generic endpoint.
# If there were non-sensitive flags intended for runtime updates, they would be added here.
ALLOWED_UPDATE_FLAGS = set()


@app.post("/api/runtime-flags")
async def update_flags(
    payload: dict,
) -> dict:
    # Iterate through the incoming payload and only update flags that are explicitly allowed.
    for key, value in payload.items():
        if key in ALLOWED_UPDATE_FLAGS:
            FEATURE_FLAGS[key] = value
        # Attempts to update flags not in ALLOWED_UPDATE_FLAGS are ignored,
        # preventing unauthorized modification of sensitive configuration.

    return FEATURE_FLAGS
