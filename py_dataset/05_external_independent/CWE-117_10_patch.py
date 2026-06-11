import logging

from django.http import HttpRequest, JsonResponse

logger = logging.getLogger(
    "catalog"
)


def search_catalog(
    request: HttpRequest,
) -> JsonResponse:
    keyword = request.GET.get(
        "q",
        "",
    )
    logger.info(
        "catalog query=%s", keyword
    )

    return JsonResponse({
        "items": [],
    })
