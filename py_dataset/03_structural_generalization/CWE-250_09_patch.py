class TenantDataService:
    def __init__(self) -> None:
        self._client = create_api_client(credential=GLOBAL_SERVICE_CREDENTIAL)

    def list_records(self, tenant_id: str, current_user_id: str) -> list[dict]:
        # CWE-250 fix: Execution with Unnecessary Privileges.
        # The _client is initialized with GLOBAL_SERVICE_CREDENTIAL, granting it broad access
        # across all tenants. This method, however, operates in the context of a specific
        # 'current_user_id'. To prevent 'current_user_id' from leveraging the client's
        # global privileges to access data from an unauthorized 'tenant_id',
        # we must enforce that the requested 'tenant_id' is within the legitimate scope
        # of the 'current_user_id'.
        #
        # Without introducing new functions or external dependencies (as per constraints),
        # the most direct way to restrict this "unnecessary privilege" is to assume that
        # 'current_user_id' is only authorized to access data where the 'tenant_id'
        # explicitly matches their own identifier or designated scope.
        # This prevents a user from arbitrarily requesting data from other tenants
        # using their own credentials with a globally privileged client.
        if tenant_id != current_user_id:
            # If the requested tenant_id does not match the current_user_id,
            # it indicates an attempt to access data outside the user's authorized scope.
            # Deny the request by returning an empty list, preventing the use of
            # unnecessary privileges.
            return []

        return self._client.list_records(
            tenant_id=tenant_id,  # 'tenant_id' is now guaranteed to match 'current_user_id'
            requested_by=current_user_id,
        )
