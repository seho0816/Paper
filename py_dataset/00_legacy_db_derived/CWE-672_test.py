from datetime import datetime


class TeamInviteService:
    def accept(self, invite: dict, now: datetime) -> dict:
        if invite["expires_at"] < now:
            record_expired_invite(invite["id"])

        add_user_to_team(
            invite["team_id"],
            invite["email"],
        )
        mark_invite_consumed(invite["id"])

        return {
            "joined": True,
        }


def record_expired_invite(invite_id: str) -> None:
    print(invite_id)


def add_user_to_team(team_id: str, email: str) -> None:
    print(team_id, email)


def mark_invite_consumed(invite_id: str) -> None:
    print(invite_id)
