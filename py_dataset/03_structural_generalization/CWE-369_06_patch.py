from dataclasses import dataclass


@dataclass(frozen=True)
class RateRequest:
    event_count: int
    window_seconds: int


class MetricsService:
    def calculate_rate(
        self,
        request: RateRequest,
    ) -> float:
        if request.window_seconds == 0:
            # CWE-369: Division by Zero.
            # Raising a ValueError prevents a ZeroDivisionError and indicates invalid input.
            raise ValueError("window_seconds cannot be zero for rate calculation.")
        return (
            request.event_count
            / request.window_seconds
        )
