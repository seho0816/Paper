from dataclasses import dataclass


@dataclass(frozen=True)
class PartnerExport:
    customer: dict
    integration_token: str


class PartnerExportService:
    def export(self, request: PartnerExport) -> None:
        partner_api.send({
            "customer": request.customer,
        })
