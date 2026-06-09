def rotate_signing_key(new_key_id: str) -> None:
    stored = key_repository.store(new_key_id)
    rotation_log.write({'new_key_id': new_key_id, 'stored': stored})
    key_repository.mark_active(new_key_id)
