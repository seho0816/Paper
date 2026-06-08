import logging

# Configure basic logging. In a real application, this setup would be more sophisticated
# (e.g., to a file, syslog, etc.) and typically done once at application startup.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RoleManagementService:
    def promote_to_manager(self, actor_id: str, target_user_id: str) -> None:
        try:
            update_user_role(target_user_id, "manager")
            send_role_change_notice(target_user_id)
            # CWE-778 Fix: Log the security-relevant event with full context, including the actor, for auditing purposes.
            logger.info(f"SECURITY_AUDIT: User '{actor_id}' successfully promoted user '{target_user_id}' to 'manager' role.")
        except Exception as e:
            # CWE-778 Fix: Log failures for security-relevant actions.
            logger.error(f"SECURITY_AUDIT_FAILURE: User '{actor_id}' failed to promote user '{target_user_id}' to 'manager' role. Error: {e}")
            raise # Re-raise the exception to maintain original error propagation behavior

def update_user_role(user_id: str, role: str) -> None:
    # CWE-778 Fix: Replace print with proper logging for better audibility and system integration.
    logger.info(f"ACTION: Updating role for user '{user_id}' to '{role}'.")


def send_role_change_notice(user_id: str) -> None:
    # CWE-778 Fix: Replace print with proper logging for better audibility and system integration.
    logger.info(f"ACTION: Sending role change notice to user '{user_id}'.")
