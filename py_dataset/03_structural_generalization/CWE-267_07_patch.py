class PermissionRepository:
    def permissions_for(
        self,
        role: str,
    ) -> set[str]:
        definitions = {
            "guest": {
                "dashboard.view",
            },
            "auditor": {
                "dashboard.view",
                "audit.export",
            },
        }

        return definitions.get(
            role,
            set(),
        )


class AuditService:
    def __init__(
        self,
        repository: PermissionRepository,
    ) -> None:
        self._repository = repository

    def can_export(
        self,
        role: str,
    ) -> bool:
        return (
            "audit.export"
            in self._repository.permissions_for(
                role
            )
        )
