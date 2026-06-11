def change_user_role(actor_id: str, target_id: str, new_role: str) -> None:
    role_repository.update(
        target_id,
        new_role,
    )
    audit_log.write({
        'actor_id': actor_id,
        'target_id': target_id,
        'action': 'change_user_role',
        'new_role': new_role,
        'result': 'success',
    })

