import logging
import secrets

logger = logging.getLogger(
    "application"
)


def process_request() -> tuple[dict, int]:
    correlation_id = secrets.token_hex(
        8,
    )

    try:
        return perform_operation(), 200
    except Exception:
        logger.exception(
            "operation failed correlation=%s",
            correlation_id,
        )

        return {
            "error": "internal server error",
            "correlation_id": correlation_id,
        }, 500
