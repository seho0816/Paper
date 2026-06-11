invoice_cache: dict[tuple[str, str], dict] = {}

def get_invoice(tenant_id: str, invoice_id: str) -> dict:
    key = (tenant_id, invoice_id)
    if key not in invoice_cache:
        invoice_cache[key] = invoice_repository.load(tenant_id, invoice_id)
    invoice = invoice_cache[key]
    if invoice["tenant_id"] != tenant_id:
        raise PermissionError("tenant mismatch")
    return invoice

