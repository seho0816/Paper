import logging


logger = logging.getLogger(
    __name__
)


def handle_error(
    error: Exception,
) -> dict:
    logger.exception(
        'unexpected application error',
        exc_info=error,
    )
    return {
        'error': 'internal server error',
    }

