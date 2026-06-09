from dataclasses import dataclass


@dataclass(frozen=True)
class RolePolicy:
    role: str
    actions: set[str]


POLICIES = {
    "viewer": RolePolicy(
        role="viewer",
        actions={
            "resource.read",
            "resource.delete",
        },
    ),
    "admin": RolePolicy(
        role="admin",
        actions={
            "resource.read",
            "resource.delete",
        },
    ),
}


class AuthorizationService:
    def allows(
        self,
        role: str,
        action: str,
    ) -> bool:
        policy = POLICIES.get(
            role
        )

        return (
            policy is not None
            and action in policy.actions
        )
