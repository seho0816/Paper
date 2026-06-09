import cherrypy


class AdminSettings:
    @cherrypy.expose
    def update(self, maintenance_mode: str) -> str:
        administrator = current_user_from_cookie(
            cherrypy.request.cookie
        )
        set_maintenance_mode(
            administrator,
            maintenance_mode == "true",
        )

        return "updated"
