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
    # CWE-117 mitigation: Neutralize newline and carriage return characters from user_agent
    # to prevent log injection and tampering.
    sanitized_user_agent = user_agent.replace("\n", "").replace("\r", "")
    logger.info(
        f"status check agent={sanitized_user_agent}"
    )

    return {
        "status": "ok",
    }
