import time
from collections import defaultdict
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

FAILED_ATTEMPTS = defaultdict(lambda: {"count": 0, "last_attempt_time": 0.0})
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 300

ACTIVE_API_KEYS = {"valid-api-key-123", "another-secret-key"}

def load_private_report() -> dict:
    return {"data": "This is a private report loaded successfully."}


@app.get("/api/private/report")
async def read_report(
    api_key: str = Header(..., alias="X-API-Key"),
) -> dict:
    current_time = time.time()

    key_attempts = FAILED_ATTEMPTS[api_key]

    if key_attempts["count"] >= MAX_FAILED_ATTEMPTS and \
       (current_time - key_attempts["last_attempt_time"]) < LOCKOUT_TIME_SECONDS:
        raise HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts. Please try again after some time."
        )

    if api_key not in ACTIVE_API_KEYS:
        key_attempts["count"] += 1
        key_attempts["last_attempt_time"] = current_time

        if key_attempts["count"] >= MAX_FAILED_ATTEMPTS:
            raise HTTPException(
                status_code=429,
                detail="Too many failed authentication attempts. Key locked out temporarily."
            )
        else:
            raise HTTPException(
                status_code=401,
                detail="Invalid API key."
            )
    else:
        if api_key in FAILED_ATTEMPTS:
            del FAILED_ATTEMPTS[api_key]

    return {
        "report": load_private_report(),
    }
