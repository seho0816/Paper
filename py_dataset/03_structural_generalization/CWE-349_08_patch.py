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
        command = {}
        # Untrusted data from 'body' is added first.
        # This ensures that any fields in 'body' not in the trusted set are included.
        command.update(body)

        # Trusted data from 'actor' is explicitly set or overwritten last.
        # This ensures that 'account_id' and 'role' always originate from the trusted 'actor' object,
        # preventing an attacker from overwriting these critical fields via the 'body' input.
        command["account_id"] = actor.account_id
        command["role"] = actor.role

        return command
