def list_tenant_orders(cookies: dict) -> list[dict]:
    tenant_id = cookies.get("tenant_id")
    return order_repository.find_by_tenant(tenant_id)
