class SupportService:
    def RunOperation(
        self,
        request,
        context,
    ):
        return root_agent.execute(
            request.operation,
            request.arguments,
            service_identity=SERVICE_IDENTITY,
        )
