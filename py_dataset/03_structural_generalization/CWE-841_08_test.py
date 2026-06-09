from dataclasses import dataclass

@dataclass(frozen=True)
class EmailChangeConfirmed:
    account_id: str
    requested_email: str

class EmailChangeConsumer:
    async def handle(self, event: EmailChangeConfirmed) -> None:
        await account_repository.update_email(
            event.account_id,
            event.requested_email,
            verified=True,
        )
