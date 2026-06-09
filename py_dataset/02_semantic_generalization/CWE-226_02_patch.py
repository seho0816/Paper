context_pool: list[dict] = []


def email_context(account: dict) -> dict:
    context = context_pool.pop() if context_pool else {}
    # CWE-226 fix: Clear the dictionary to prevent information exposure
    # from previously used objects in the pool.
    context.clear()
    context["display_name"] = account["display_name"]
    context["plan"] = account["plan"]
    return context
