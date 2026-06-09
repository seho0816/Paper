from dataclasses import dataclass


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
            f"<id>{profile.partner_id}</id>"
            f"<name>{profile.display_name}</name>"
            f"<plan>{profile.plan}</plan>"
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
