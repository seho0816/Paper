class RoleManagementService:
    def promote_to_manager(self, actor_id: str, target_user_id: str) -> None:
        update_user_role(target_user_id, "manager")
        send_role_change_notice(target_user_id)


def update_user_role(user_id: str, role: str) -> None:
    print(user_id, role)


def send_role_change_notice(user_id: str) -> None:
    print(user_id)
