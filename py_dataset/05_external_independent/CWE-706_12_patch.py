def resolve_award_credit(_root, info, display_name: str, credits: int) -> dict:
    recipient = info.context.accounts.find_by_display_name(
        display_name
    )
    # CWE-706: Improper Neutralization of Special Elements used in a Format String
    # While not a classic format string vulnerability, this CWE can broadly cover
    # situations where externally controlled input leads to unexpected behavior
    # or crashes if not properly neutralized. In this case, if 'display_name'
    # leads to no valid recipient (e.g., 'recipient' is None or an empty dict),
    # accessing recipient['account_id'] would cause a TypeError or KeyError,
    # leading to a denial of service.
    # The fix ensures that 'recipient' is valid and contains the expected key
    # before proceeding, neutralizing the impact of an invalid 'display_name'
    # by safely handling the "not found" scenario.
    if recipient and 'account_id' in recipient:
        info.context.wallets.add_credit(
            recipient['account_id'],
            credits,
        )
        return {'recipient': recipient['account_id']}
    else:
        # If the recipient is not found or is invalid, the operation cannot complete.
        # Return a dictionary indicating that no recipient was found.
        # This prevents a crash and maintains the expected return type.
        return {'recipient': None}
