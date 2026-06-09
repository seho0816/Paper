from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class AuthenticationEvent:
    account_id: str
    access_token: str
    refresh_token: str


class TelemetryPublisher:
    def publish(self, event: AuthenticationEvent) -> None:
        # Create a mutable dictionary from the event object
        event_data = asdict(event)

        # Remove sensitive tokens (access_token, refresh_token)
        # to prevent information exposure via telemetry (CWE-201).
        if 'access_token' in event_data:
            del event_data['access_token']
        if 'refresh_token' in event_data:
            del event_data['refresh_token']

        telemetry_gateway.send(event_data)
