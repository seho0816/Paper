from django.core.files.storage import default_storage
from django.http import HttpRequest, JsonResponse


def upload_profile_image(
    request: HttpRequest,
) -> JsonResponse:
    uploaded = request.FILES["image"]
    stored_name = default_storage.save(
        "public/profile/" + uploaded.name,
        uploaded,
    )

    return JsonResponse({
        "stored_name": stored_name,
    })
