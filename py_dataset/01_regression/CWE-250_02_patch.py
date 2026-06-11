from some_backend_sdk import create_backend_client

def load_my_profile(current_user_id: str) -> dict:
    # Removed 'service_role=True' as loading a single user's profile does not
    # require elevated service-level privileges. A default or user-scoped client
    # is sufficient and adheres to the principle of least privilege (CWE-250).
    client = create_backend_client()
    return client.table("profiles").select("*").eq("id", current_user_id).single()
