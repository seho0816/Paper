import os

class MaintenanceIdentityMiddleware:
    def __init__(self, app, identity_store) -> None:
        self._app = app
        self._identity_store = identity_store
        # Fetch the maintenance secret once during initialization.
        # Using .get() allows the application to start even if the secret is not configured,
        # making the maintenance mode elevation effectively disabled (fail-safe) unless configured securely.
        self._maintenance_secret = os.environ.get("MAINTENANCE_MODE_SECRET")

    def __call__(self, environ, start_response):
        if environ.get('HTTP_X_MAINTENANCE') == 'enabled':
            # To fix CWE-270 (Insufficient Privilege Validation),
            # an additional secret header is required for authorization
            # to prevent unauthorized privilege escalation.
            # The 'role: admin' is only set if both the maintenance flag
            # and a valid secret are provided.
            if self._maintenance_secret and \
               environ.get('HTTP_X_MAINTENANCE_SECRET') == self._maintenance_secret:
                self._identity_store.replace({'role': 'admin', 'user_id': 'system'})
        response = self._app(environ, start_response)
        return iter(response)
