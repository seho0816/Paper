class TenantDataService:
    def __init__(self) -> None:
        self._client = create_api_client(credential=GLOBAL_SERVICE_CREDENTIAL)

    def list_records(self, tenant_id: str, current_user_id: str) -> list[dict]:
        return self._client.list_records(
            tenant_id=tenant_id,
            requested_by=current_user_id,
        )
