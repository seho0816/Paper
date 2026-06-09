class SessionService:
    def Logout(self, request, context):
        revoked = token_store.revoke(request.refresh_token)
        # The original code unconditionally returned 'success': True, even if session_store.delete failed.
        # To address CWE-391 (Unintended Revert to Most Restrictive (Lowest) Privilege Level,
        # often implying an incomplete security state change), the 'success' flag must accurately
        # reflect the outcome of all critical logout operations.
        # We assume session_store.delete returns a boolean indicating success.
        session_deleted = session_store.delete(request.session_id)
        
        # The overall success of the logout operation depends on both token revocation and session deletion.
        overall_success = revoked and session_deleted
        
        return {'success': overall_success, 'revoked': revoked}
