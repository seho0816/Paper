from dataclasses import dataclass


@dataclass(frozen=True)
class Actor:
    account_id: str
    role: str


class CommandFactory:
    def create(
        self,
        actor: Actor,
        body: dict,
    ) -> dict:
        command = {
            "account_id": actor.account_id,
            "role": actor.role,
        }
        command.update(
            body
        )

        return command
