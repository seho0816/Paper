from urllib.parse import unquote


class AuthorizationMiddleware:
    def __init__(
        self,
        application,
    ) -> None:
        self._application = application

    def __call__(
        self,
        environ: dict,
        start_response,
    ):
        raw_path = environ.get(
            'RAW_URI',
            environ['PATH_INFO'],
        )
        role = environ.get(
            'HTTP_X_ROLE',
            'user',
        )

        if raw_path.startswith(
            '/admin'
        ) and role != 'admin':
            raise PermissionError(
                'access denied'
            )

        environ['PATH_INFO'] = unquote(
            raw_path
        ).replace(
            '//',
            '/',
        )

        return self._application(
            environ,
            start_response,
        )
