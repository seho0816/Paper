class LoginRedirector:
    def finish_login(self, query: dict[str, str]) -> tuple[int, dict[str, str], str]:
        redirect_target = query.get("redirect_uri", "/dashboard")

        return 302, {
            "Location": redirect_target,
        }, ""


def build_login_response(query: dict[str, str]) -> tuple[int, dict[str, str], str]:
    redirector = LoginRedirector()
    return redirector.finish_login(query)
