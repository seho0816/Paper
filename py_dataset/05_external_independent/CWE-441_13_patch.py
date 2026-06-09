class SupportService:
    def RunOperation(
        self,
        request,
        context,
    ):
        # Define a whitelist of allowed operations.
        # This prevents arbitrary command execution via user-controlled input.
        ALLOWED_OPERATIONS = [
            "get_system_status",
            "list_available_services",
            "update_service_config",
            "restart_specific_service",
            "retrieve_diagnostic_logs",
            "ping_external_endpoint",
        ]

        # Validate the requested operation against the predefined whitelist.
        # This addresses CWE-441 by ensuring that the backend data (operations)
        # executed by root_agent are strictly controlled and not based on unvalidated
        # front-end (user) input.
        if request.operation not in ALLOWED_OPERATIONS:
            raise ValueError(f"Operation '{request.operation}' is not allowed.")

        return root_agent.execute(
            request.operation,
            request.arguments,
            service_identity=SERVICE_IDENTITY,
        )
