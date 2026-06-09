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
        allowed = True

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
