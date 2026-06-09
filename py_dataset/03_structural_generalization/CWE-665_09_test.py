class MiddlewareRegistration:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.require_authentication = False
        self.require_csrf = False

class MiddlewareRegistry:
    def register_admin_handler(self, handler) -> None:
        registration = MiddlewareRegistration(handler)
        self._entries.append(registration)
