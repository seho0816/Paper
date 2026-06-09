from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()


@app.get("/api/private/billing")
async def read_billing_summary(
    request: Request,
) -> JSONResponse:
    origin = request.headers.get("origin", "")

    response = JSONResponse({
        "plan": "enterprise",
        "outstanding_balance": 180000,
    })

    if origin.endswith("example.com"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response
