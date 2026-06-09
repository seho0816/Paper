def resolve_export_invoice(_, info, input: dict) -> dict:
    info.context["principal"] = {
        "account_id": input["account_id"],
        "role": input.get("role", "viewer"),
        "workspace_id": input["workspace_id"],
    }
    return export_invoice(info.context["principal"], input["invoice_id"])
