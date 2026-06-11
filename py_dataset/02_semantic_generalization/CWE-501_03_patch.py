def resolve_export_invoice(_, info, input: dict) -> dict:
    # CWE-501: Trust Boundary Violation
    # The 'principal' object, representing the authenticated user's identity and roles,
    # should be constructed from trusted context information, not from untrusted user input.
    # We assume 'info.context' contains a 'user' object (or similar key)
    # that holds the authenticated user's details, populated by an authentication middleware.

    # Retrieve the trusted authenticated user data from the context.
    # This assumes that 'info.context["user"]' exists and contains the necessary
    # 'account_id', 'role', and 'workspace_id' for the authenticated user.
    # If 'user' or any required key within it is missing, it will raise a KeyError,
    # consistent with how the original code would behave if 'input' keys were missing.
    authenticated_user_data = info.context["user"]

    info.context["principal"] = {
        "account_id": authenticated_user_data["account_id"],
        "role": authenticated_user_data.get("role", "viewer"),
        "workspace_id": authenticated_user_data["workspace_id"],
    }
    return export_invoice(info.context["principal"], input["invoice_id"])
