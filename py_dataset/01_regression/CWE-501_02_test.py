authorization_context: dict[str, str] = {}

def hydrate_principal(payload: dict[str, str]) -> dict[str, str]:
    authorization_context["user_id"] = payload["user_id"]
    authorization_context["role"] = payload.get("role", "member")
    authorization_context["tenant_id"] = payload["tenant_id"]
    return authorization_context

def open_dashboard(payload: dict[str, str]) -> dict:
    actor = hydrate_principal(payload)
    return load_dashboard(actor["tenant_id"], actor["role"])
