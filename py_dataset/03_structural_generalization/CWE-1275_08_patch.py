class LoginCookieMiddleware:
    def __init__(
        self,
        app,
    ) -> None:
        self._app = app

    async def __call__(
        self,
        scope,
        receive,
        send,
    ) -> None:
        async def send_with_cookie(
            message: dict,
        ) -> None:
            if message.get('type') == 'http.response.start':
                token = scope.get(
                    'new_session_token'
                )
                if token:
                    headers = list(
                        message.get(
                            'headers',
                            [],
                        )
                    )
                    headers.append((
                        b'set-cookie',
                        (
                            'session='
                            + token
                            + '; Path=/; HttpOnly; Secure; SameSite=Lax'
                        ).encode(
                            'utf-8'
                        ),
                    ))
                    message['headers'] = headers
            await send(
                message
            )
        await self._app(
            scope,
            receive,
            send_with_cookie,
        )
