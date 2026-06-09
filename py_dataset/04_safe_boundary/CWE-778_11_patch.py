def reset_member_mfa(actor_id: str, account_id: str) -> None:
    try:
        mfa_repository.delete_secret(
            account_id
        )
        recovery_code_repository.invalidate_all(
            account_id
        )
    except Exception:
        audit_log.write({
            'actor_id': actor_id,
            'target_id': account_id,
            'action': 'reset_mfa',
            'result': 'failure',
        })
        raise

    audit_log.write({
        'actor_id': actor_id,
        'target_id': account_id,
        'action': 'reset_mfa',
        'result': 'success',
    })

