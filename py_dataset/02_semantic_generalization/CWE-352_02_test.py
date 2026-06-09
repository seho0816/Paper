from fastapi import Cookie, FastAPI, Form

app = FastAPI()


@app.post("/api/account/alias")
async def update_alias(
    alias: str = Form(...),
    session_id: str = Cookie(...),
) -> dict:
    account_id = resolve_account_from_session(
        session_id,
    )
    update_account_alias(
        account_id,
        alias,
    )

    return {
        "updated": True,
    }
