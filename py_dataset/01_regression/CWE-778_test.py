def change_user_role(actor_id: str, target_id: str, new_role: str) -> None:
    role_repository.update(
        target_id,
        new_role,
    )
