import time
from flask import request


# For demonstration purposes, these constants are defined here.
# In a real application, they would be loaded from a secure configuration.
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 300  # 5 minutes

def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    user = users.get(username)

    # Prevent user enumeration: do not distinguish between invalid username and invalid password.
    if user is None:
        return {"error": "invalid credentials"}, 401

    now = time.time()

    # Check if the user account is currently locked out
    if user.get("lockout_until") and user["lockout_until"] > now:
        return {"error": "Account locked. Please try again later."}, 401

    if user["password"] != password:
        # Increment failed attempt count for the user
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1

        # If max attempts reached, lock the account
        if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
            user["lockout_until"] = now + LOCKOUT_TIME_SECONDS
            user["failed_attempts"] = 0  # Reset attempts after lockout to prevent indefinite lockout or prepare for next unlock
            return {"error": "Too many failed login attempts. Account locked."}, 401
        else:
            return {"error": "invalid credentials"}, 401
    else:
        # Successful login: reset failed attempts and clear any lockout status
        if "failed_attempts" in user:
            user["failed_attempts"] = 0
        if "lockout_until" in user:
            del user["lockout_until"]
        return {"authenticated": True}
