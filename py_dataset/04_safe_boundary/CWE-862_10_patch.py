def approve_refund(
    actor: dict,
    refund: dict,
) -> None:
    policy = RefundAuthorizationPolicy(
        actor,
        refund,
    )

    if not policy.can_approve():
        raise PermissionError(
            "refund approval denied"
        )

    # CWE-862 Fix: Add specific authorization checks that might be missing from the generic policy.
    # For example, ensure an actor cannot approve their own refund, which is a common security policy.
    # This assumes 'refund' dictionary contains a 'requester_id' and 'actor' dictionary contains an 'id'.
    if refund.get("requester_id") == actor["id"]:
        raise PermissionError(
            "refund approval denied: cannot approve own refund"
        )

    mark_refund_approved(
        refund["id"],
        actor["id"],
    )
