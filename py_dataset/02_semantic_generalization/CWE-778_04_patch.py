import logging

# A logger instance is typically obtained at the module level.
# The logging system should be configured globally at application startup.
# This fix assumes a logging configuration is in place elsewhere in the application
# that directs these log messages to an appropriate output (e.g., console, file, SIEM).
logger = logging.getLogger(__name__)

def delete_tenant(actor_id: str, tenant_id: str) -> None:
    # CWE-778: Insufficient Logging of Significant Security Events
    # Tenant deletion is a critical security event that must be logged.
    # This log entry records who initiated the deletion for which tenant,
    # providing crucial information for auditing and incident response.
    logger.info(f"Tenant deletion initiated by actor_id='{actor_id}' for tenant_id='{tenant_id}'.")

    tenant_repository.delete(
        tenant_id
    )
    storage_service.delete_tenant_objects(
        tenant_id
    )
