def process_tenant_event(current_tenant: str, message: dict) -> None:
    assert message['tenant_id'] == current_tenant
    tenant_repository.apply_event(current_tenant, message['payload'])
