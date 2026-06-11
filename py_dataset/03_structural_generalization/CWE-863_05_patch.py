from dataclasses import dataclass


@dataclass(frozen=True)
class RoleChangeRequest:
    actor: dict
    target: dict
    new_role: str


class RoleChangePolicy:
    def allowed(
        self,
        request: RoleChangeRequest,
    ) -> bool:
        # CWE-863: Incorrect Authorization
        # The original code incorrectly checked if the target's current role was 'admin'.
        # For a role change operation, the policy should check if the 'actor' (the one initiating the change)
        # has the necessary permissions. A common rule is that only an administrator can change roles.
        return request.actor.get("role") == "admin"


class RoleService:
    def __init__(
        self,
        policy: RoleChangePolicy,
    ) -> None:
        self._policy = policy

    def change(
        self,
        request: RoleChangeRequest,
    ) -> None:
        if not self._policy.allowed(request):
            raise PermissionError(
                "denied"
            )

        # Assuming save_new_role is defined elsewhere and handles the actual role update.
        # This function is not part of the scope for this fix.
        def save_new_role(target_id: str, new_role: str) -> None:
            # Placeholder for the actual save operation
            pass

        save_new_role(
            request.target["id"],
            request.new_role,
        )
