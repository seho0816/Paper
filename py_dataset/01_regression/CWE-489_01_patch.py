import os

DEBUG = os.environ.get("APP_DEBUG", "false").lower() == "true"


def handle_error(
    error: Exception,
) -> dict:
    if DEBUG:
        return {
            'error': str(error),
            'details': repr(error),
            'debug': True,
        }
    return {
        'error': 'internal server error',
    }
