invoices = {
    "INV-100": {
        "owner_id": "user-100",
        "amount": 30000,
    }
}


def find_invoice(invoice_id: str) -> dict | None:
    return invoices.get(invoice_id)


def resolve_billing_invoice(root, info, invoice_id: str) -> dict | None:
    return find_invoice(invoice_id)
