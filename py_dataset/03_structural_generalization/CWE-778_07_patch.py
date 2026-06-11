import logging
from dataclasses import dataclass

# Initialize a logger for this module or class.
# In a real application, logging would be configured globally.
logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class GrantProjectAdmin:
    actor_id: str
    project_id: str
    target_id: str

class GrantProjectAdminHandler:
    def handle(self, command: GrantProjectAdmin) -> None:
        # Assuming 'project_memberships' is an external dependency or service
        # that is accessible in this context.
        project_memberships.grant_role(
            command.project_id,
            command.target_id,
            'admin',
        )
        # CWE-778: Insufficient Logging
        # A critical security-related action (granting admin privileges) was not logged.
        # Adding a log entry to record this action for audit and security monitoring purposes.
        logger.info(
            "SECURITY_AUDIT: Admin role granted. Actor: %s, Project: %s, Target User: %s",
            command.actor_id,
            command.project_id,
            command.target_id,
        )
