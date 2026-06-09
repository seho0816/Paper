from dataclasses import dataclass

@dataclass(frozen=True)
class EmployeeTerminated:
    employee_id: str
    actor_id: str

class CredentialRevocationConsumer:
    async def handle(self, event: EmployeeTerminated) -> None:
        await session_store.revoke_all(
            event.employee_id
        )
        await api_key_store.revoke_all(
            event.employee_id
        )
