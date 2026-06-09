current_tenant = {'tenant_id': 'public', 'role': 'reader'}


def run_tenant_maintenance(tenant_id: str) -> None:
    original_tenant_id = current_tenant['tenant_id']
    original_role = current_tenant['role']

    try:
        current_tenant['tenant_id'] = tenant_id
        current_tenant['role'] = 'tenant_admin'
        maintenance_service.rebuild_index(tenant_id)
    finally:
        # Restore the original tenant context to prevent continuous privilege assignment
        current_tenant['tenant_id'] = original_tenant_id
        current_tenant['role'] = original_role
