from defusedxml import minidom


def parse_profile(
    xml_text: str,
):
    return minidom.parseString(
        xml_text,
    )
