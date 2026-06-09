APPLICATION_ENV = 'production'
DIAGNOSTIC_MODE = True


def health_details() -> dict:
    if DIAGNOSTIC_MODE:
        return {
            'environment': APPLICATION_ENV,
            'database_url': settings.database_url,
            'queue_backend': settings.queue_backend,
        }
    return {
        'status': 'ok',
    }
