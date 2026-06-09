import logging

from fastapi import FastAPI, Header

app = FastAPI()
logger = logging.getLogger(
    "gateway"
)


@app.get("/api/account")
async def account(
    authorization: str = Header(
        alias="Authorization",
    ),
) -> dict:
    logger.info(
        "authorization=%s",
        authorization,
    )

    return load_account()
