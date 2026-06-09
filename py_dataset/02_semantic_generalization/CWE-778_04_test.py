def delete_tenant(actor_id: str, tenant_id: str) -> None:
    tenant_repository.delete(
        tenant_id
    )
    storage_service.delete_tenant_objects(
        tenant_id
    )
