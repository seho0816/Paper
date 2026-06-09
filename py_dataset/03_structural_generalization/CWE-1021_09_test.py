class SecurityHeadersMiddleware:
    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        async def wrapped_send(message: dict) -> None:
            if message['type'] == 'http.response.start':
                headers = list(message.get('headers', []))
                headers.extend([
                    (b'x-content-type-options', b'nosniff'),
                    (b'referrer-policy', b'no-referrer'),
                ])
                message['headers'] = headers
            await send(message)

        await self._app(scope, receive, wrapped_send)
