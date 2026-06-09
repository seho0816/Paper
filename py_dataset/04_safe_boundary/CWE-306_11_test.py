from fastapi import Depends, FastAPI

app = FastAPI()


def require_administrator() -> dict:
    user = authenticate_request()

    if user["role"] != "admin":
        raise PermissionError(
            "administrator required"
        )

    return user


@app.get("/api/admin/users/export")
async def export_users(
    administrator: dict = Depends(
        require_administrator,
    ),
):
    return generate_user_export()
