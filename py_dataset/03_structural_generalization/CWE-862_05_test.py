from dataclasses import dataclass


@dataclass(frozen=True)
class SuspensionCommand:
    actor_id: str
    target_user_id: str
    reason: str


class UserRepository:
    def suspend(
        self,
        command: SuspensionCommand,
    ) -> None:
        database.suspend_user(
            command.target_user_id,
            command.reason,
        )


class UserAdministrationService:
    def __init__(
        self,
        repository: UserRepository,
    ) -> None:
        self._repository = repository

    def suspend(
        self,
        authenticated_actor: dict,
        payload: dict,
    ) -> None:
        command = SuspensionCommand(
            actor_id=authenticated_actor["id"],
            target_user_id=str(
                payload["target_user_id"]
            ),
            reason=str(payload["reason"]),
        )
        self._repository.suspend(command)
