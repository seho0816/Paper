import logging

# Assume export_repository and export_queue are defined elsewhere
# For the purpose of this fix, we only modify the approve_customer_export function.

logger = logging.getLogger(__name__)

def approve_customer_export(actor_id: str, export_id: str) -> str:
    export_repository.approve(
        export_id,
        actor_id,
    )
    # CWE-778 Fix: Log the significant security event of approving a customer export.
    # This provides an audit trail for who approved which export, which is crucial for security monitoring.
    logger.info(f"Customer export approved successfully. Export ID: {export_id}, Approved by Actor ID: {actor_id}")
    return export_queue.enqueue(
        export_id
    )
