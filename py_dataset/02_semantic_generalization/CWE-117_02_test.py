import logging

from fastapi import FastAPI, Header

app = FastAPI()
logger = logging.getLogger(
    "gateway"
)


@app.get("/api/status")
async def status(
    user_agent: str = Header(
        default="",
        alias="User-Agent",
    ),
) -> dict:
    logger.info(
        f"status check agent={user_agent}"
    )

    return {
        "status": "ok",
    }
