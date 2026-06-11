import logging
from dataclasses import dataclass

# As per the original code, session_store and api_key_store are assumed to be
# defined and accessible in the scope where CredentialRevocationConsumer is used.
# For example:
# session_store = YourSessionStoreImplementation()
# api_key_store = YourApiKeyStoreImplementation()

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class EmployeeTerminated:
    employee_id: str
    actor_id: str

class CredentialRevocationConsumer:
    async def handle(self, event: EmployeeTerminated) -> None:
        # CWE-778 Fix: Insufficient Logging of Sensitive Information
        # Critical security events, such as employee termination leading to
        # credential revocation, must be logged for auditing and security monitoring.
        logger.info(
            "Initiating credential revocation for employee_id=%s due to termination by actor_id=%s",
            event.employee_id,
            event.actor_id
        )

        await session_store.revoke_all(
            event.employee_id
        )
        await api_key_store.revoke_all(
            event.employee_id
        )
