from dataclasses import dataclass

@dataclass(frozen=True)
class WorkspaceInviteEvent:
    workspace_id: str
    invited_display_name: str

class WorkspaceInviteConsumer:
    def handle(self, event: WorkspaceInviteEvent) -> None:
        account = account_directory.find_by_display_name(
            event.invited_display_name
        )
        invitation_repository.create(
            workspace_id=event.workspace_id,
            account_id=account['id'],
        )
