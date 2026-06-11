import os
import uuid
from django.core.files.storage import default_storage
from django.http import HttpRequest, JsonResponse


def upload_profile_image(
    request: HttpRequest,
) -> JsonResponse:
    if "image" not in request.FILES:
        return JsonResponse(
            {"error": "No image file provided."},
            status=400
        )

    uploaded = request.FILES["image"]

    allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
    allowed_content_types = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
    ]

    file_extension = os.path.splitext(uploaded.name)[1].lower()
    content_type = uploaded.content_type

    if file_extension not in allowed_extensions or content_type not in allowed_content_types:
        return JsonResponse(
            {"error": "Invalid file type. Only JPG, JPEG, PNG, GIF, WEBP images are allowed."},
            status=400
        )

    safe_filename = f"{uuid.uuid4()}{file_extension}"
    destination_path = os.path.join("public", "profile", safe_filename)

    stored_name = default_storage.save(
        destination_path,
        uploaded,
    )

    return JsonResponse({
        "stored_name": stored_name,
    })
