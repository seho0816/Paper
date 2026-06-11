import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    account_id: str


class TenantContextFactory:
    def create(self, cookies: dict) -> TenantContext:
        tenant_id_str = cookies.get("tenant_id")
        account_id_str = cookies.get("account_id")

        # CWE-565: Reliance on Cookies without Validation and Integrity Checking
        # Fix: Add validation for cookie contents.
        # Ensure 'tenant_id' and 'account_id' are present, not empty, and are in a valid format (e.g., UUID).
        # This prevents KeyErrors, processing of empty/malformed IDs, and adds a basic level of content validation.

        if not tenant_id_str:
            raise ValueError("Missing or empty 'tenant_id' in cookies.")
        if not account_id_str:
            raise ValueError("Missing or empty 'account_id' in cookies.")

        try:
            # Validate tenant_id format (assuming UUID format for robust identifiers)
            uuid.UUID(tenant_id_str)
        except ValueError as e:
            raise ValueError(f"Invalid 'tenant_id' format in cookies: {tenant_id_str}") from e

        try:
            # Validate account_id format (assuming UUID format for robust identifiers)
            uuid.UUID(account_id_str)
        except ValueError as e:
            raise ValueError(f"Invalid 'account_id' format in cookies: {account_id_str}") from e

        return TenantContext(
            tenant_id=tenant_id_str,
            account_id=account_id_str,
        )


class TenantReportService:
    def __init__(self, factory: TenantContextFactory) -> None:
        self._factory = factory

    def generate(self, cookies: dict) -> bytes:
        context = self._factory.create(cookies)
        # Assuming 'report_repository' is an external dependency that handles
        # the actual data retrieval and further authorization checks (e.g.,
        # ensuring the context.tenant_id belongs to the authenticated user).
        # The fix above ensures the tenant_id extracted from cookies is at least
        # well-formed before being passed to this repository.
        return report_repository.export_tenant(context.tenant_id)
