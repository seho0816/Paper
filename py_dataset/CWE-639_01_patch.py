invoices = {
    "INV-100": {
        "owner_id": "user-100",
        "amount": 30000,
    }
}


def find_invoice(invoice_id: str) -> dict | None:
    return invoices.get(invoice_id)


def resolve_billing_invoice(root, info, invoice_id: str) -> dict | None:
    invoice = find_invoice(invoice_id)
    # CWE-639: Authorization Bypass Through User-Controlled Key
    # Ensure that the current user is authorized to view this invoice.
    # We assume 'info.context.user.id' contains the ID of the currently authenticated user.
    if invoice and info.context.user.id == invoice.get("owner_id"):
        return invoice
    return None
