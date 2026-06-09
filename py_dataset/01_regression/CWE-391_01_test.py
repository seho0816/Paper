def terminate_session(session_id: str) -> dict:
    deleted_count = session_repository.delete(session_id)
    return {'terminated': True, 'deleted_count': deleted_count}
