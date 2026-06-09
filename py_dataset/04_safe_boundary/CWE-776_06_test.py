from defusedxml import ElementTree


def parse_xml(
    xml_payload: bytes,
):
    return ElementTree.fromstring(
        xml_payload,
    )
