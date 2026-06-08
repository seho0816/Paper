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
        # CWE-267: Privilege Overwrite by Lower Privileged User
        # The original code returned a direct reference to the set within PERMISSION_MATRIX.
        # This allowed callers to modify the global permission set, potentially leading to privilege escalation or corruption.
        # By returning a copy of the set, we ensure that any modifications by the caller do not affect the central permission matrix.
        return PERMISSION_MATRIX.get(role, set()).copy()
