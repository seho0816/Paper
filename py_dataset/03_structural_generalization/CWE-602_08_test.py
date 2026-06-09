def resolve_request_loan(_root, info, amount: int, approved_limit: int) -> dict:
    if amount > approved_limit:
        raise ValueError('limit exceeded')
    application = info.context.loans.create({
        'account_id': info.context.account_id,
        'amount': amount,
        'approved_limit': approved_limit,
    })
    return {'application_id': application['id']}
