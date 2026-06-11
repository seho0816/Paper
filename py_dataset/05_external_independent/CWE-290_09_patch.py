import grpc

class AccountService:
    def GetPrivateProfile(
        self,
        request,
        context,
    ):
        metadata = dict(
            context.invocation_metadata()
        )
        
        # CWE-290 fix: Do not trust 'x-account-id' directly from client-supplied metadata.
        # Instead, rely on an account ID that has been verified by an authentication
        # interceptor and made available in a trusted manner within the context.
        # It is assumed that a gRPC authentication interceptor processes
        # incoming requests, verifies credentials, and then injects the
        # authenticated user's ID into the context under a distinct, internal,
        # and trusted key (e.g., '_authenticated_account_id').
        
        authenticated_account_id = metadata.get("_authenticated_account_id")

        if not authenticated_account_id:
            # If the authenticated ID is not present, it means the request
            # was either not authenticated, or authentication failed.
            # In a secure system, an authentication interceptor should typically
            # have aborted the call already. As a failsafe within the method,
            # we explicitly abort here.
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Authentication required or failed.")

        # Use the trusted, verified account ID.
        account_id = authenticated_account_id

        return load_private_profile(
            account_id
        )
