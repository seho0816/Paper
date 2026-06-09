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

        # CWE-636 fix: Default to deny if the decision is not explicitly 'allow' or 'deny'.
        # The original code implicitly allowed access (returned True) for unknown states,
        # leading to a "fail-open" vulnerability.
        return False
