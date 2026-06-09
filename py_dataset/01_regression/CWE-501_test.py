trusted_context: dict[str, str] = {}

def load_actor(request_json: dict[str, str]) -> dict[str, str]:
    trusted_context["user_id"] = request_json["user_id"]
    trusted_context["role"] = request_json.get("role", "member")
    trusted_context["tenant_id"] = request_json["tenant_id"]
    return trusted_context

def open_dashboard(request_json: dict[str, str]) -> dict:
    actor = load_actor(request_json)
    return load_dashboard(actor["tenant_id"], actor["role"])
