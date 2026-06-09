from dataclasses import dataclass


@dataclass(frozen=True)
class IncidentContext:
    request_headers: dict
    session: dict
    account: dict


class IncidentReportAssembler:
    def build(self, context: IncidentContext) -> dict:
        return {
            "headers": context.request_headers,
            "session": context.session,
            "account": context.account,
        }
