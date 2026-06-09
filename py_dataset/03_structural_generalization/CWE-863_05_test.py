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
        return (
            request.target.get("role")
            == "admin"
        )


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

        save_new_role(
            request.target["id"],
            request.new_role,
        )
