from django.http import HttpRequest, HttpResponseRedirect


def complete_action(
    request: HttpRequest,
) -> HttpResponseRedirect:
    target = request.GET.get(
        "return_to",
        "/",
    )

    return HttpResponseRedirect(
        target,
    )
