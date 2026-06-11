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
        # 'database' is assumed to be an existing object or globally available,
        # as per the original code. No changes are made to its implied definition.
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
        # CWE-862 fix: Add authorization check.
        # This check verifies if the 'authenticated_actor' has the necessary
        # 'admin' role to perform user suspension.
        # It assumes 'authenticated_actor' contains a 'roles' key, which is a list of strings.
        # If the application uses a different authorization scheme (e.g., specific permissions),
        # this logic should be adapted accordingly.
        required_role = "admin"
        if required_role not in authenticated_actor.get("roles", []):
            raise PermissionError("Actor is not authorized to suspend users.")

        command = SuspensionCommand(
            actor_id=authenticated_actor["id"],
            target_user_id=str(
                payload["target_user_id"]
            ),
            reason=str(payload["reason"]),
        )
        self._repository.suspend(command)
