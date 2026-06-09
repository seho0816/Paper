import traceback

from django.http import JsonResponse


def process_payment(request):
    try:
        return JsonResponse(
            charge_payment(
                request.POST,
            )
        )
    except Exception as error:
        return JsonResponse(
            {
                "message": str(error),
                "traceback": traceback.format_exc(),
            },
            status=500,
        )
