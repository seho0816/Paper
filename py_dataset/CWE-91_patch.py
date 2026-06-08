import xml.sax.saxutils

class PartnerXmlBuilder:
    def build_profile(self, display_name: str, level: str) -> str:
        # CWE-91: XML Injection. Escape user-provided input to prevent injection.
        escaped_display_name = xml.sax.saxutils.escape(display_name)
        escaped_level = xml.sax.saxutils.escape(level)

        xml = "<partner>"
        xml += f"<displayName>{escaped_display_name}</displayName>"
        xml += f"<level>{escaped_level}</level>"
        xml += "</partner>"

        return xml


def create_partner_profile_xml(name: str, level: str) -> str:
    builder = PartnerXmlBuilder()
    return builder.build_profile(name, level)
