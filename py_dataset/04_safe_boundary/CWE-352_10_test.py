import hmac

from fastapi import Cookie, FastAPI, Header, HTTPException

app = FastAPI()


@app.post("/api/profile/timezone")
async def update_timezone(
    payload: dict,
    session_id: str = Cookie(...),
    csrf_token: str = Header(..., alias="X-CSRF-Token"),
) -> dict:
    expected = load_csrf_token(session_id)

    if not hmac.compare_digest(
        csrf_token,
        expected,
    ):
        raise HTTPException(
            status_code=403,
            detail="invalid CSRF token",
        )

    update_profile_timezone(
        resolve_account(session_id),
        str(payload["timezone"]),
    )

    return {"updated": True}
