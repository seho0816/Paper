import cherrypy


class AdminSettings:
    @cherrypy.expose
    def update(self, maintenance_mode: str) -> str:
        # CWE-352: Cross-Site Request Forgery (CSRF) mitigation.
        # 1. Enforce POST method for state-changing operations.
        if cherrypy.request.method != 'POST':
            raise cherrypy.HTTPError(405, "Method Not Allowed")

        # 2. Validate CSRF token.
        # This assumes a CSRF token has been securely generated and stored in
        # cherrypy.session['csrf_token'] by a preceding mechanism (e.g., a GET endpoint
        # rendering the form, or a global CherryPy hook) and is expected in the request parameters.
        session_csrf_token = cherrypy.session.get('csrf_token')
        request_csrf_token = cherrypy.request.params.get('csrf_token')

        if not session_csrf_token or not request_csrf_token or session_csrf_token != request_csrf_token:
            raise cherrypy.HTTPError(403, "Forbidden") # Generic message to avoid information leakage

        # Original, now protected, code logic:
        administrator = current_user_from_cookie(
            cherrypy.request.cookie
        )
        set_maintenance_mode(
            administrator,
            maintenance_mode == "true",
        )

        return "updated"
