from fastapi import FastAPI, Request, Response

app = FastAPI()


@app.get("/api/private/profile")
async def read_private_profile(
    request: Request,
    response: Response,
) -> dict:
    caller_origin = request.headers.get("origin", "")

    response.headers["Access-Control-Allow-Origin"] = caller_origin
    response.headers["Access-Control-Allow-Credentials"] = "true"

    return {
        "email": "member@example.com",
        "membership_level": "premium",
    }
