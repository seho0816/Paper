invoice_cache: dict[tuple[str, str], dict] = {}

# Assuming 'database' is available in the execution environment or imported elsewhere
# For example:
# import some_database_module as database 

def load_invoice(tenant_id: str, invoice_id: str) -> dict:
    return database.fetch_one(tenant_id=tenant_id, resource_id=invoice_id)

def get_invoice(tenant_id: str, invoice_id: str) -> dict:
    cache_key = (tenant_id, invoice_id)
    if cache_key not in invoice_cache:
        invoice_cache[cache_key] = load_invoice(tenant_id, invoice_id)
    return invoice_cache[cache_key]
