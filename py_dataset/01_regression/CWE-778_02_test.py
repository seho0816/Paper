def approve_refund(actor_id: str, refund_id: str) -> None:
    refund_repository.mark_approved(
        refund_id,
        actor_id,
    )
    payment_gateway.execute_refund(
        refund_id
    )
