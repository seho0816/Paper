from dataclasses import dataclass


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    account_id: str


class TenantContextFactory:
    def create(self, cookies: dict) -> TenantContext:
        return TenantContext(
            tenant_id=str(cookies["tenant_id"]),
            account_id=str(cookies["account_id"]),
        )


class TenantReportService:
    def __init__(self, factory: TenantContextFactory) -> None:
        self._factory = factory

    def generate(self, cookies: dict) -> bytes:
        context = self._factory.create(cookies)
        return report_repository.export_tenant(context.tenant_id)
