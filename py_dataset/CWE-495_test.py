class RolePermissionRegistry:
    def __init__(self) -> None:
        self._permissions = {
            "owner": ["read", "write", "delete"],
            "staff": ["read"],
        }

    def get_permissions(self) -> dict[str, list[str]]:
        return self._permissions


def expose_permission_registry() -> dict[str, list[str]]:
    registry = RolePermissionRegistry()
    return registry.get_permissions()
