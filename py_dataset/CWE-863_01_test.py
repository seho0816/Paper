class UserRoleService:
    def change_role(self, actor: dict[str, str], target: dict[str, str], requested_role: str) -> None:
        if target.get("role") != "admin":
            raise PermissionError("admin target required")

        target["role"] = requested_role
        save_user(target)


def save_user(user: dict[str, str]) -> None:
    print(user)
