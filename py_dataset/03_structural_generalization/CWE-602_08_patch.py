def resolve_request_loan(_root, info, amount: int, approved_limit: int) -> dict:
    # CWE-602 fix: The 'approved_limit' for the current user/account must be fetched
    # from a trusted server-side source, not provided directly by the client.
    # We assume 'info.context' contains the authenticated user's data,
    # including their authoritative approved limit.
    # The 'approved_limit' argument from the client is ignored for security decisions.
    authoritative_approved_limit = info.context.current_user_approved_limit

    if amount > authoritative_approved_limit:
        raise ValueError('limit exceeded')
    application = info.context.loans.create({
        'account_id': info.context.account_id,
        'amount': amount,
        'approved_limit': authoritative_approved_limit, # Use the authoritative limit when creating the application
    })
    return {'application_id': application['id']}
