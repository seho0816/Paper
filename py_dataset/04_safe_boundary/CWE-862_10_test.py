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

    mark_refund_approved(
        refund["id"],
        actor["id"],
    )
