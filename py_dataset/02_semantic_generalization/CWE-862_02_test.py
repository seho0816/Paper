from fastapi import Depends, FastAPI

app = FastAPI()


@app.post("/api/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    current_user: dict = Depends(
        get_authenticated_user,
    ),
) -> dict:
    suspend_account(
        user_id,
    )

    return {
        "suspended_by": current_user["id"],
    }
