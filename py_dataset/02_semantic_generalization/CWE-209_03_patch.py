from django.http import JsonResponse


def process_payment(request):
    try:
        return JsonResponse(
            charge_payment(
                request.POST,
            )
        )
    except Exception as error:
        # CWE-209: Sensitive information disclosure via detailed error messages.
        # Removing the full traceback from the public error response.
        return JsonResponse(
            {
                "message": "An internal server error occurred.", # Providing a generic message for security
            },
            status=500,
        )
