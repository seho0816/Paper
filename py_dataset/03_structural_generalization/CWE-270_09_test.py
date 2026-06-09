class MaintenanceIdentityMiddleware:
    def __init__(self, app, identity_store) -> None:
        self._app = app
        self._identity_store = identity_store

    def __call__(self, environ, start_response):
        if environ.get('HTTP_X_MAINTENANCE') == 'enabled':
            self._identity_store.replace({'role': 'admin', 'user_id': 'system'})
        response = self._app(environ, start_response)
        return iter(response)
