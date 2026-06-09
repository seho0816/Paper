context_pool: list[dict] = []


def email_context(account: dict) -> dict:
    context = context_pool.pop() if context_pool else {}
    context["display_name"] = account["display_name"]
    context["plan"] = account["plan"]
    return context
