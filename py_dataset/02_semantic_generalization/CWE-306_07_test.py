from fastapi import FastAPI

app = FastAPI()


@app.post("/api/admin/accounts/{account_id}/unlock")
async def unlock_account(
    account_id: str,
) -> dict:
    clear_account_lock(
        account_id,
    )

    return {
        "unlocked": True,
    }
