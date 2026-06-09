from lxml import etree


def parse_partner_xml(
    xml_body: bytes,
):
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
    )

    return etree.fromstring(
        xml_body,
        parser,
    )
