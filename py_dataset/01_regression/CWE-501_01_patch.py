security_context: dict[str, str] = {}

def build_current_user(form_data: dict[str, str]) -> dict[str, str]:
    security_context["user_id"] = form_data["user_id"]
    # CWE-501: Trust Boundary Violation.
    # The 'role' attribute, which defines user privileges, should not be
    # determined by untrusted user input (form_data).
    # Instead of allowing form_data.get("role", "member") which permits
    # privilege escalation, the role is set to a secure, default value.
    security_context["role"] = "member"
    security_context["tenant_id"] = form_data["tenant_id"]
    return security_context

def open_dashboard(form_data: dict[str, str]) -> dict:
    actor = build_current_user(form_data)
    # Assuming load_dashboard is an existing function.
    return load_dashboard(actor["tenant_id"], actor["role"])
