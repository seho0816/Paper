class AccountService:
    def ChangeEmail(self, request, context):
        # CWE-501: Trust Boundary Violation has been removed.
        # Previously, context.principal was constructed directly from untrusted
        # invocation metadata (client-supplied headers).
        # It is now assumed that context.principal is securely populated by a trusted
        # authentication mechanism (e.g., an authentication interceptor or middleware)
        # before this method is invoked.
        return update_email(context.principal, request.new_email)
