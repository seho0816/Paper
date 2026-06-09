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
        return (
            request.event_count
            / request.window_seconds
        )
