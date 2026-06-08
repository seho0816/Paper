import urllib.parse

class LoginRedirector:
    def finish_login(self, query: dict[str, str]) -> tuple[int, dict[str, str], str]:
        redirect_target = query.get("redirect_uri", "/dashboard")

        # Parse the redirect_target to check if it's an absolute URL or uses a scheme.
        parsed_uri = urllib.parse.urlparse(redirect_target)

        # If the URI has a scheme (e.g., http, https, javascript) or a netloc (hostname),
        # it is considered an external or untrusted absolute/scheme-relative URL in this context.
        # Without a known trusted domain for validation, such URLs are rejected to prevent Open Redirect.
        # The redirect is then defaulted to a safe internal path.
        if parsed_uri.scheme or parsed_uri.netloc:
            redirect_target = "/dashboard"

        return 302, {
            "Location": redirect_target,
        }, ""


def build_login_response(query: dict[str, str]) -> tuple[int, dict[str, str], str]:
    redirector = LoginRedirector()
    return redirector.finish_login(query)
