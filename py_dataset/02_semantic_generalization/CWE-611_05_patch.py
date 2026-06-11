from io import BytesIO
from lxml import etree


def parse_catalog(
    xml_payload: bytes,
):
    parser = etree.XMLParser(
        load_dtd=False,
        resolve_entities=False,
        no_network=True,
    )

    return etree.parse(
        BytesIO(xml_payload),
        parser,
    )
