from fastapi import FastAPI, HTTPException

app = FastAPI()


@app.get("/api/recovery-question/{username}")
async def recovery_question(
    username: str,
) -> dict:
    account = find_account(
        username
    )

    if account is None:
        raise HTTPException(
            status_code=404,
            detail="unknown username",
        )

    return {
        "question": account[
            "recovery_question"
        ],
    }
