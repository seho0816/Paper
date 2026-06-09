from defusedxml import ElementTree


def parse_invoice(
    xml_payload: bytes,
):
    return ElementTree.fromstring(
        xml_payload,
    )
