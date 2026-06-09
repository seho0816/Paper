security_context: dict[str, str] = {}

def build_current_user(form_data: dict[str, str]) -> dict[str, str]:
    security_context["user_id"] = form_data["user_id"]
    security_context["role"] = form_data.get("role", "member")
    security_context["tenant_id"] = form_data["tenant_id"]
    return security_context

def open_dashboard(form_data: dict[str, str]) -> dict:
    actor = build_current_user(form_data)
    return load_dashboard(actor["tenant_id"], actor["role"])
