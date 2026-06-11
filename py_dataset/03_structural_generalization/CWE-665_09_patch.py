class MiddlewareRegistration:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.require_authentication = False
        self.require_csrf = False

class MiddlewareRegistry:
    def register_admin_handler(self, handler) -> None:
        registration = MiddlewareRegistration(handler)
        # CWE-665 fix: For admin handlers, ensure authentication and CSRF are required by default.
        # The initial values in MiddlewareRegistration are suitable for general handlers,
        # but for admin specific handlers, these security requirements should be explicitly set to True
        # as part of their proper initialization in this context.
        registration.require_authentication = True
        registration.require_csrf = True
        self._entries.append(registration)
