current_tenant = {'tenant_id': 'public', 'role': 'reader'}


def run_tenant_maintenance(tenant_id: str) -> None:
    current_tenant['tenant_id'] = tenant_id
    current_tenant['role'] = 'tenant_admin'
    maintenance_service.rebuild_index(tenant_id)
