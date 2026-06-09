from fastapi import FastAPI, Header, HTTPException

app = FastAPI()


@app.get("/api/private/report")
async def read_report(
    api_key: str = Header(..., alias="X-API-Key"),
) -> dict:
    if api_key not in ACTIVE_API_KEYS:
        raise HTTPException(
            status_code=401,
            detail="invalid key",
        )

    return {
        "report": load_private_report(),
    }
