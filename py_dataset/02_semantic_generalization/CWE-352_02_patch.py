from fastapi import Cookie, FastAPI, Form, Header, HTTPException, status
import secrets

app = FastAPI()

# Placeholder for actual session/account resolution and update functions
# In a real application, these would interact with a database or other services.
def resolve_account_from_session(session_id: str):
    # This is a mock function. Replace with actual session validation logic.
    if session_id == "valid_session_abc":
        return 123
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

def update_account_alias(account_id: int, alias: str):
    # This is a mock function. Replace with actual account update logic.
    print(f"Account {account_id} alias updated to: {alias}")
    # Simulate database update success
    return True

# Dependency to verify CSRF token (Double Submit Cookie pattern or Synchronizer Token Pattern with headers)
# The client is expected to send the same token in a cookie named '_csrf_token'
# and in a custom header named 'X-CSRF-TOKEN'.
async def verify_csrf_token(
    csrf_cookie: str = Cookie(..., alias="_csrf_token"),
    csrf_header: str = Header(..., alias="X-CSRF-TOKEN"),
):
    if not secrets.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch",
        )
    return True


@app.post("/api/account/alias", dependencies=[Depends(verify_csrf_token)])
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
