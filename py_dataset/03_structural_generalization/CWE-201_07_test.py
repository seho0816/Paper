from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class AuthenticationEvent:
    account_id: str
    access_token: str
    refresh_token: str


class TelemetryPublisher:
    def publish(self, event: AuthenticationEvent) -> None:
        telemetry_gateway.send(asdict(event))
