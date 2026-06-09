def issue_approval_code(
    approval_store,
    request_id: str,
) -> str:
    sequence = approval_store.increment(
        'approval-code-sequence'
    )
    code = f'APPROVE-{sequence}'
    approval_store.bind(
        request_id,
        code,
    )
    return code
