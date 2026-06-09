# For demonstration purposes, a simple mock of server-side sessions.
# In a real application, this would be a secure database lookup, a caching system (e.g., Redis),
# or a proper session management system integrated with a web framework.
_SERVER_SIDE_SESSIONS = {
    "secure_session_id_123": {"user_id": 1, "plan": "pro"},
    "secure_session_id_456": {"user_id": 2, "plan": "enterprise"},
    "secure_session_id_789": {"user_id": 3, "plan": "basic"},
}

def _get_user_plan_from_session(session_id: str | None) -> str | None:
    """
    Retrieves the user's plan from a trusted server-side session store using the session_id.
    This prevents reliance on client-controlled cookie values for security decisions (CWE-565).
    """
    if not session_id:
        return None
    session_data = _SERVER_SIDE_SESSIONS.get(session_id)
    return session_data.get("plan") if session_data else None

# Assume generate_premium_report is defined elsewhere in the application
# For the purpose of making the code snippet runnable, a placeholder implementation is included.
def generate_premium_report() -> bytes:
    """Generates the premium report content."""
    return b"Premium Report Content"

def export_premium_report(cookies: dict) -> bytes:
    # CWE-565 fix: Do not rely directly on the 'plan' cookie value for security decisions.
    # Instead, use a session ID from cookies to retrieve trusted user plan information from a server-side source.
    session_id = cookies.get("session_id") # Assuming 'session_id' is the cookie used to identify the session
    user_plan = _get_user_plan_from_session(session_id)

    if user_plan not in {"pro", "enterprise"}:
        raise PermissionError("premium plan required")
    return generate_premium_report()
