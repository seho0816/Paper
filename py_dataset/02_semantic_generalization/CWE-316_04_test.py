recovery_answer_cache: dict[str, str] = {}


def verify_recovery_answer(account_id: str, answer: str) -> bool:
    recovery_answer_cache[account_id] = answer
    return recovery_repository.matches(account_id, answer)
