def resolve_delete_invoice(
    _root,
    info,
    invoice_id: str,
) -> dict:
    try:
        allowed = info.context.policy.allows(
            info.context.user_id,
            "invoice.delete",
            invoice_id,
        )
    except TimeoutError:
        # CWE-636: The original code allowed access (allowed = True) if the policy check timed out,
        # leading to a "fail-open" authorization vulnerability. This bypasses the security policy
        # if the policy service is slow or unresponsive.
        # To fix this, in a security-sensitive context, an authorization check failure (like a timeout)
        # should result in denial of access ("fail-close").
        allowed = False

    if not allowed:
        raise PermissionError(
            "permission denied"
        )

    delete_invoice(
        invoice_id
    )

    return {
        "deleted": True,
    }
