PERMISSION_MATRIX = {
    "guest": {
        "project.read",
        "project.delete",
    },
    "editor": {
        "project.read",
        "project.update",
    },
    "administrator": {
        "project.read",
        "project.update",
        "project.delete",
    },
}


class PermissionResolver:
    def permissions_for(self, role: str) -> set[str]:
        return PERMISSION_MATRIX.get(role, set())
