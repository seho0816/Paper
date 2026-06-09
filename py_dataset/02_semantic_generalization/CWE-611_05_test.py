from io import BytesIO
from lxml import etree


def parse_catalog(
    xml_payload: bytes,
):
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
        no_network=False,
    )

    return etree.parse(
        BytesIO(xml_payload),
        parser,
    )
