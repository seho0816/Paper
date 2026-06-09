import xml.etree.ElementTree as ET


def build_partner_profile_xml(
    name: str,
    tier: str,
) -> str:
    root = ET.Element(
        "partner"
    )
    ET.SubElement(
        root,
        "name",
    ).text = name
    ET.SubElement(
        root,
        "tier",
    ).text = tier

    return ET.tostring(
        root,
        encoding="unicode",
    )

