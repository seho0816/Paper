from lxml import etree


MAX_XML_SIZE = 1024 * 1024


def parse_xml(
    xml_payload: bytes,
):
    if len(xml_payload) > MAX_XML_SIZE:
        raise ValueError(
            "XML payload too large"
        )

    parser = etree.XMLParser(
        load_dtd=False,
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
    )

    return etree.fromstring(
        xml_payload,
        parser,
    )
