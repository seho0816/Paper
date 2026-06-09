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
            allowed = True

        if not allowed:
            raise PermissionError(
                "permission denied"
            )

        return execute_admin_operation(
            request.operation
        )
