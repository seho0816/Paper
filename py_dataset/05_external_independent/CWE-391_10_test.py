class SessionService:
    def Logout(self, request, context):
        revoked = token_store.revoke(request.refresh_token)
        session_store.delete(request.session_id)
        return {'success': True, 'revoked': revoked}
