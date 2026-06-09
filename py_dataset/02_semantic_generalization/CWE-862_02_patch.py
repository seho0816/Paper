from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()

# Placeholder for get_authenticated_user
# In a real application, this function would authenticate the user (e.g., via a JWT token)
# and return their details, including their assigned roles or permissions.
# For demonstration, we simulate a user without 'admin' privileges by default.
async def get_authenticated_user() -> dict:
    # This is a mock user. In a real system, this would be fetched from a database
    # or parsed from an authentication token, including role information.
    # To demonstrate the CWE-862 fix, we assume the default authenticated user
    # does NOT have administrative privileges required for this action.
    return {"id": "some_user_id", "username": "testuser", "role": "user"}

# Placeholder for suspend_account
# This function would contain the actual business logic to suspend a user account.
def suspend_account(user_id: str):
    # In a real application, this would interact with a database or another service
    # to update the user's status to suspended.
    print(f"Action: User '{user_id}' has been marked for suspension.")


@app.post("/api/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    current_user: dict = Depends(
        get_authenticated_user,
    ),
) -> dict:
    # CWE-862 Fix: Implement authorization check
    # Ensure that only users with the 'admin' role can suspend other accounts.
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to suspend users")

    suspend_account(
        user_id,
    )

    return {
        "message": f"User {user_id} suspended successfully.",
        "suspended_by": current_user["id"],
    }
