import logging

logger = logging.getLogger(__name__)
# In a real application, logging would be configured globally at application startup.
# For this isolated snippet to effectively demonstrate the fix by ensuring log output,
# a basic configuration is added if no handlers are already present.
# This prevents 'No handlers could be found for logger "..."' messages.
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Assume 'api_key_repository' is an existing object with a 'revoke' method.
# Its definition is outside the scope of this specific fix.
# For example:
# class ApiKeyRepository:
#     def revoke(self, api_key_id: str):
#         print(f"DEBUG: Revoking API key: {api_key_id}")
#         # Simulate a possible error for testing the exception path
#         # if api_key_id == "error_key":
#         #     raise ValueError("Simulated revocation failure")
# api_key_repository = ApiKeyRepository()


def revoke_api_key(actor_id: str, api_key_id: str) -> None:
    try:
        api_key_repository.revoke(
            api_key_id
        )
        logger.info(f"API key '{api_key_id}' successfully revoked by actor '{actor_id}'.")
    except Exception as e:
        logger.error(f"Failed to revoke API key '{api_key_id}' requested by actor '{actor_id}': {e}", exc_info=True)
        # Re-raise the exception to maintain the original function's error propagation behavior
        raise
