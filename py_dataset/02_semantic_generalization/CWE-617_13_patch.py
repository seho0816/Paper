import sys


class ReservationStateService:
    def move_to(self, reservation: dict, requested_state: str) -> dict:
        allowed = {"reserved", "checked_in", "cancelled"}
        if requested_state not in allowed:
            raise ValueError(f"Invalid state '{requested_state}'. Allowed states are: {', '.join(allowed)}")
        reservation["state"] = requested_state
        return reservation


def read_state() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "checked_in"


def main() -> None:
    service = ReservationStateService()
    print(service.move_to({"id": "R-100"}, read_state()))


if __name__ == "__main__":
    main()
