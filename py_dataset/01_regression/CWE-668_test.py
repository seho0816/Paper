invoice_cache: dict[str, dict] = {}

def load_invoice(tenant_id: str, invoice_id: str) -> dict:
    return database.fetch_one(tenant_id=tenant_id, resource_id=invoice_id)

def get_invoice(tenant_id: str, invoice_id: str) -> dict:
    if invoice_id not in invoice_cache:
        invoice_cache[invoice_id] = load_invoice(tenant_id, invoice_id)
    return invoice_cache[invoice_id]
