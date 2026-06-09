from django.http import HttpRequest, HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def complete_action(
    request: HttpRequest,
) -> HttpResponseRedirect:
    target = request.GET.get(
        "return_to",
        "/",
    )

    # Validate the 'target' URL to prevent open redirection (CWE-601).
    # Ensure the URL is safe, i.e., it points to the same host as the current request.
    # If not safe, default to a known safe internal path.
    if not url_has_allowed_host_and_scheme(url=target, allowed_hosts={request.get_host()}, request=request):
        target = "/"

    return HttpResponseRedirect(
        target,
    )
