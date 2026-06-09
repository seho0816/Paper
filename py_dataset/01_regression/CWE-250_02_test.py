def load_my_profile(current_user_id: str) -> dict:
    client = create_backend_client(service_role=True)
    return client.table("profiles").select("*").eq("id", current_user_id).single()
