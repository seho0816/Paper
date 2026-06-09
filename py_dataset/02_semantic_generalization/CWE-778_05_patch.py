import logging

# In a real application, logging would be configured globally.
# For this snippet, we initialize a logger for this module.
logger = logging.getLogger(__name__)

def unlock_account(actor_id: str, account_id: str) -> None:
    # Perform the action to clear the account lock.
    account_repository.clear_lock(
        account_id
    )
    # CWE-778 Fix: Log the significant security event that an account lock has been cleared.
    # This helps in auditing, incident response, and forensic analysis.
    logger.info(f"SECURITY_EVENT: Account lock cleared. Actor: '{actor_id}', Target Account: '{account_id}'.")

    # Perform the action to reset the login counter.
    login_counter_repository.reset(
        account_id
    )
    # CWE-778 Fix: Log the significant security event that the login counter has been reset.
    logger.info(f"SECURITY_EVENT: Login counter reset. Actor: '{actor_id}', Target Account: '{account_id}'.")
