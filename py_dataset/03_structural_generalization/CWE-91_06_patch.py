from dataclasses import dataclass
from xml.sax.saxutils import escape


@dataclass(frozen=True)
class PartnerProfile:
    partner_id: str
    display_name: str
    plan: str


class PartnerXmlBuilder:
    def build(
        self,
        profile: PartnerProfile,
    ) -> str:
        return (
            "<partner>"
            f"<id>{escape(profile.partner_id)}</id>"
            f"<name>{escape(profile.display_name)}</name>"
            f"<plan>{escape(profile.plan)}</plan>"
            "</partner>"
        )


class PartnerService:
    def __init__(
        self,
        builder: PartnerXmlBuilder,
    ) -> None:
        self._builder = builder

    def serialize(
        self,
        payload: dict,
    ) -> str:
        return self._builder.build(
            PartnerProfile(
                partner_id=str(
                    payload["partner_id"]
                ),
                display_name=str(
                    payload["display_name"]
                ),
                plan=str(
                    payload["plan"]
                ),
            )
        )
