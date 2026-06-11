from defusedxml import ElementTree


def parse_invoice(
    xml_payload: bytes,
):
    # CWE-611 (XXE) mitigation:
    # defusedxml.ElementTree's DefusedXMLParser forbids external entities by default.
    # Explicitly creating and passing the parser with 'forbid_external=True'
    # makes this mitigation clear and ensures no external entity references are processed.
    parser = ElementTree.DefusedXMLParser(
        forbid_dtd=True,
        forbid_entities=True,
        forbid_external=True
    )
    return ElementTree.fromstring(
        xml_payload,
        parser=parser,
    )
