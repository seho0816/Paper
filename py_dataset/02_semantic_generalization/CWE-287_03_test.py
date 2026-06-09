from fastapi import FastAPI, Header, HTTPException

app = FastAPI()


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

    return {
        "report": load_private_report(),
    }
