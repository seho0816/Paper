from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def update_shipping_address(
    request: HttpRequest,
) -> JsonResponse:
    address = request.POST.get("address", "")
    request.user.profile.shipping_address = address
    request.user.profile.save()

    return JsonResponse({
        "updated": True,
    })
