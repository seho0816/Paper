from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# CWE-942: Permissive Cross-domain Policy with Untrusted Domains fix.
# Replace the broad `endswith` check with a specific whitelist of allowed origins.
# These origins should be explicitly trusted domains where the frontend application resides.
# In a real-world application, this list would typically be loaded from secure configuration
# (e.g., environment variables) rather than hardcoded.
ALLOWED_ORIGINS = {
    "https://example.com",
    "http://example.com",
    "https://www.example.com",
    "http://www.example.com",
}

@app.get("/api/private/billing")
async def read_billing_summary(
    request: Request,
) -> JSONResponse:
    origin = request.headers.get("origin", "")

    response = JSONResponse({
        "plan": "enterprise",
        "outstanding_balance": 180000,
    })

    # Validate the origin against the explicitly allowed origins whitelist.
    # This prevents subdomains or other untrusted domains ending with "example.com"
    # from being allowed, fixing CWE-942 by enforcing a strict allowlist.
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response
