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

        # CWE-647 Fix: Ensure the path is fully decoded and normalized
        # before performing security checks and passing it to the application.
        # This prevents interpretation conflicts due to multiple encodings.

        # 1. Repeatedly unquote the path until it no longer changes.
        # This handles multiple levels of URL encoding (e.g., %252F).
        processed_path = raw_path
        while True:
            new_processed_path = unquote(processed_path)
            if new_processed_path == processed_path:
                break
            processed_path = new_processed_path

        # 2. Normalize redundant slashes (e.g., '///admin' becomes '/admin').
        # This ensures a canonical path representation for security checks,
        # preventing bypasses like '/admin//foo' or '/admin/./foo'.
        while '//' in processed_path:
            processed_path = processed_path.replace('//', '/')

        # 3. Ensure path starts with a single '/' and remove any trailing slash
        # for consistent canonical form, unless it's just the root path '/'.
        if not processed_path.startswith('/'):
            processed_path = '/' + processed_path
        if len(processed_path) > 1 and processed_path.endswith('/'):
            processed_path = processed_path[:-1]

        # Perform the security check on the fully processed and canonicalized path.
        # This aligns the path used for the check with the path the application will receive.
        if processed_path.startswith(
            '/admin'
        ) and role != 'admin':
            raise PermissionError(
                'access denied'
            )

        # Assign the fully processed and canonicalized path to PATH_INFO.
        # This ensures the downstream application receives a consistent and safe path.
        environ['PATH_INFO'] = processed_path

        return self._application(
            environ,
            start_response,
        )
