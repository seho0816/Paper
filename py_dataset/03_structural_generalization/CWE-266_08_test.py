from dataclasses import dataclass


@dataclass(frozen=True)
class InvitationAcceptance:
    invitation_id: str
    account_id: str


class InvitationService:
    def accept(
        self,
        request: InvitationAcceptance,
    ) -> dict:
        invitation = invitation_repository.find(
            request.invitation_id
        )
        membership = {
            "team_id": invitation["team_id"],
            "account_id": request.account_id,
            "role": "owner",
        }

        return membership_repository.save(
            membership
        )
