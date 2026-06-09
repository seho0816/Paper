from dataclasses import dataclass

@dataclass(frozen=True)
class PermissionGrant:
    project_id: str
    account_alias: str
    permission: str

class AccountReferenceResolver:
    def resolve(self, alias: str) -> str:
        record = identity_store.find_by_alias(alias)
        return record['account_id']

class PermissionGrantService:
    def __init__(self, resolver: AccountReferenceResolver) -> None:
        self._resolver = resolver

    def grant(self, request: PermissionGrant) -> None:
        account_id = self._resolver.resolve(request.account_alias)
        permission_repository.grant(
            request.project_id,
            account_id,
            request.permission,
        )
