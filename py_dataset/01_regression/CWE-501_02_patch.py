def hydrate_principal(payload: dict[str, str]) -> dict[str, str]:
    # CWE-501 Trust Boundary Violation:
    # Removed the global 'authorization_context' to prevent shared state issues
    # that could lead to one user's context being leaked or overwritten by another.
    # Instead, a new dictionary is created for each call, ensuring isolation.
    principal_context: dict[str, str] = {}
    principal_context["user_id"] = payload["user_id"]
    principal_context["role"] = payload.get("role", "member")
    principal_context["tenant_id"] = payload["tenant_id"]
    return principal_context

# Assuming 'load_dashboard' is defined elsewhere and its import/availability
# is handled by the surrounding application context.
# Example placeholder for 'load_dashboard' (DO NOT INCLUDE IN FINAL OUTPUT):
# def load_dashboard(tenant_id: str, role: str) -> dict:
#     # ... actual dashboard loading logic ...
#     return {"dashboard_status": f"Loaded for tenant {tenant_id} with role {role}"}

def open_dashboard(payload: dict[str, str]) -> dict:
    actor = hydrate_principal(payload)
    # The 'actor' here is an isolated context specific to this request,
    # preventing trust boundary violations due to shared state.
    return load_dashboard(actor["tenant_id"], actor["role"])
