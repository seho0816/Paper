from django.http import JsonResponse
from django.views.decorators.http import require_POST

@require_POST
def reserve_seats(request):
    seat_price = int(request.POST["seat_price"])
    seat_count = int(request.POST["seat_count"])
    reservation = save_reservation(
        event_id=request.POST["event_id"],
        seats=seat_count,
        payable=seat_price * seat_count,
    )
    return JsonResponse({"reservation_id": reservation.id})
