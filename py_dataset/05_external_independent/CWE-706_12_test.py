def resolve_award_credit(_root, info, display_name: str, credits: int) -> dict:
    recipient = info.context.accounts.find_by_display_name(
        display_name
    )
    info.context.wallets.add_credit(
        recipient['account_id'],
        credits,
    )
    return {'recipient': recipient['account_id']}
