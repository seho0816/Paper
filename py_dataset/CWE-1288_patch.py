from dataclasses import dataclass
from datetime import date


@dataclass
class RentalPeriod:
    starts_on: date
    ends_on: date

    def __post_init__(self):
        if self.starts_on > self.ends_on:
            raise ValueError("Rental period 'starts_on' cannot be after 'ends_on'.")


class RentalReservationService:
    def reserve(self, room_id: str, starts_on: date, ends_on: date) -> dict:
        period = RentalPeriod(
            starts_on=starts_on,
            ends_on=ends_on,
        )

        return {
            "room_id": room_id,
            "period": period,
        }
