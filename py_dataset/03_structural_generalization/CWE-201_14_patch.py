class TelemetryClient:
    def emit(self, event_name: str, properties: dict) -> None:
        print(event_name, properties)


class RecoveryEventTracker:
    def __init__(self, telemetry: TelemetryClient) -> None:
        self.telemetry = telemetry

    def track_request(self, user_id: str, email: str, recovery_token: str) -> None:
        self.telemetry.emit(
            "account_recovery_started",
            {
                "user_id": user_id,
                "email": email,
                # CWE-201: Information Exposure Through Sent Data.
                # The recovery_token is a sensitive credential and should not be exposed in telemetry logs.
                # It has been removed from the properties dictionary.
            },
        )
