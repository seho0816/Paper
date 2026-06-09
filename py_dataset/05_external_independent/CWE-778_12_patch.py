import logging

# Initialize a logger for the module.
# In a real application, logging configuration (e.g., handlers, formatters)
# would be set up globally, typically at application startup.
logger = logging.getLogger(__name__)

class DirectoryAdminService:
    def DisableAccount(self, request, context):
        # Assume 'account_repository' and 'session_repository' are defined and accessible
        # within the scope where this service operates (e.g., globally or dependency injected).

        account_repository.disable(
            request.account_id
        )
        session_repository.revoke_all(
            request.account_id
        )
        
        # CWE-778 fix: Insufficient Logging
        # Add a log entry for this critical security-sensitive action.
        # This provides an audit trail for account disablement events.
        # Using parameterized logging to prevent potential log injection if account_id could contain malicious characters.
        logger.info("User account '%s' has been successfully disabled and all active sessions revoked.", request.account_id)
        
        return {'disabled': True}
