APPLICATION_ENV = 'production'
DIAGNOSTIC_MODE = True


def health_details() -> dict:
    if DIAGNOSTIC_MODE:
        details = {
            'environment': APPLICATION_ENV,
        }
        # CWE-489: Active Debug Code.
        # Sensitive configuration details (database_url, queue_backend)
        # should not be exposed in a production environment, even if
        # diagnostic mode is enabled.
        if APPLICATION_ENV != 'production':
            # Assume 'settings' object is available from elsewhere,
            # as it's used in the original vulnerable code.
            details['database_url'] = settings.database_url
            details['queue_backend'] = settings.queue_backend
        return details
    return {
        'status': 'ok',
    }
