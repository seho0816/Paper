from dataclasses import dataclass


@dataclass(frozen=True)
class RefundApproval:
    actor_id: str
    refund_id: str


class RefundRepository:
    def mark_approved(
        self,
        approval: RefundApproval,
    ) -> None:
        database.approve_refund(
            approval.refund_id,
            approval.actor_id,
        )


class RefundService:
    def __init__(
        self,
        repository: RefundRepository,
    ) -> None:
        self._repository = repository

    def approve(
        self,
        current_user: dict,
        refund_id: str,
    ) -> None:
        self._repository.mark_approved(
            RefundApproval(
                actor_id=current_user["id"],
                refund_id=refund_id,
            )
        )
