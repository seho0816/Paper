recovery_answer_cache: dict[str, str] = {}


def verify_recovery_answer(account_id: str, answer: str) -> bool:
    return recovery_repository.matches(account_id, answer)
