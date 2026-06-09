import rule_engine


def select_accounts(
    expression: str,
    accounts: list[dict],
) -> list[dict]:
    rule = rule_engine.Rule(
        expression
    )

    return [
        account
        for account in accounts
        if rule.matches(
            account
        )
    ]
