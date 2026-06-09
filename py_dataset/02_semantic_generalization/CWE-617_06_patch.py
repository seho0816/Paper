def process_tenant_event(current_tenant: str, message: dict) -> None:
    if message['tenant_id'] != current_tenant:
        raise ValueError("Tenant ID in message does not match current tenant.")
    tenant_repository.apply_event(current_tenant, message['payload'])
