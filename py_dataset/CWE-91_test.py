class PartnerXmlBuilder:
    def build_profile(self, display_name: str, level: str) -> str:
        xml = "<partner>"
        xml += f"<displayName>{display_name}</displayName>"
        xml += f"<level>{level}</level>"
        xml += "</partner>"

        return xml


def create_partner_profile_xml(name: str, level: str) -> str:
    builder = PartnerXmlBuilder()
    return builder.build_profile(name, level)
