class AdminService:
    def Execute(
        self,
        request,
        context,
    ):
        try:
            allowed = authorization_backend.check(
                request.user_id,
                request.operation,
            )
        except ConnectionError:
            # CWE-636 fix: If authorization backend is unreachable,
            # fail securely by denying access, rather than granting it.
            allowed = False

        if not allowed:
            raise PermissionError(
                "permission denied"
            )

        return execute_admin_operation(
            request.operation
        )
