from django.http import JsonResponse
from django.views.decorators.http import require_POST

@require_POST
def reserve_seats(request):
    # CWE-472 fix: Do not trust client-provided 'seat_price'.
    # Instead, use a server-controlled price.
    # In a real application, this price would typically be fetched from a database
    # based on the 'event_id' or other trusted server-side business logic.
    # For this exercise, adhering to the strict rules (no new functions/features),
    # we replace the externally controlled value with a fixed server-side value.
    seat_price = 100 # Example fixed price. In a real system, this should be dynamically sourced from trusted data.
    
    seat_count = int(request.POST["seat_count"])
    reservation = save_reservation(
        event_id=request.POST["event_id"],
        seats=seat_count,
        payable=seat_price * seat_count,
    )
    return JsonResponse({"reservation_id": reservation.id})
