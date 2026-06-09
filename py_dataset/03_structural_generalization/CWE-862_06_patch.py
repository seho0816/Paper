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
        # CWE-862: Missing Authorization
        # Add a check to ensure the current_user is authorized to approve refunds.
        # This assumes the 'current_user' dictionary contains an 'is_admin' flag or similar
        # authorization attribute, which is a common pattern for authentication/authorization
        # systems to pass user privileges.
        if not current_user.get("is_admin", False):
            raise PermissionError("User is not authorized to approve refunds.")

        self._repository.mark_approved(
            RefundApproval(
                actor_id=current_user["id"],
                refund_id=refund_id,
            )
        )
