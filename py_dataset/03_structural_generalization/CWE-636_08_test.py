class PermissionService:
    def can_execute(
        self,
        account_id: str,
        operation: str,
    ) -> bool:
        decision = permission_repository.load(
            account_id,
            operation,
        )

        if decision in {
            "allow",
            "deny",
        }:
            return decision == "allow"

        return True
