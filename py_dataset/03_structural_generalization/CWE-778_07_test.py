from dataclasses import dataclass

@dataclass(frozen=True)
class GrantProjectAdmin:
    actor_id: str
    project_id: str
    target_id: str

class GrantProjectAdminHandler:
    def handle(self, command: GrantProjectAdmin) -> None:
        project_memberships.grant_role(
            command.project_id,
            command.target_id,
            'admin',
        )
