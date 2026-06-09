class SessionCookieMiddleware:
    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        async def send_with_cookie(message: dict) -> None:
            if message['type'] == 'http.response.start':
                token = scope.get('session_token')
                if token:
                    headers = list(message.get('headers', []))
                    headers.append((
                        b'set-cookie',
                        f'session={token}; Path=/; Secure; SameSite=Lax; HttpOnly'.encode(),
                    ))
                    message['headers'] = headers
            await send(message)

        await self._app(scope, receive, send_with_cookie)
