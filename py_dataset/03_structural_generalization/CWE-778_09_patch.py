import logging
from dataclasses import dataclass

# Initialize a logger for this module/class
logger = logging.getLogger(__name__)

# These variables are assumed to be defined elsewhere in the application context,
# as per the original code's structure.
# For a minimal patch, we do not define them here.
# database: Any database connection object with a transaction context manager
# password_repository: Any repository object with a replace method
# session_repository: Any repository object with a revoke_all method

@dataclass(frozen=True)
class PasswordResetByAdmin:
    actor_id: str
    account_id: str
    temporary_hash: str

class AdministrativePasswordService:
    def reset(self, request: PasswordResetByAdmin) -> None:
        with database.transaction():
            password_repository.replace(
                request.account_id,
                request.temporary_hash,
            )
            session_repository.revoke_all(
                request.account_id
            )
            # CWE-778: Insufficient Logging of Sensitive Events
            # Add logging for the sensitive administrative password reset event.
            # Log who performed the action (actor_id) and for which account (account_id).
            # Avoid logging the sensitive temporary_hash itself.
            logger.info(
                "Administrative password reset performed by actor_id='%s' for account_id='%s'.",
                request.actor_id,
                request.account_id
            )
