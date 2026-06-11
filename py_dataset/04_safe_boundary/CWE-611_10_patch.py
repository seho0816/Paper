from lxml import etree


def parse_xml(
    xml_payload: bytes,
):
    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        max_element_tree_depth=1000,
    )

    return etree.fromstring(
        xml_payload,
        parser,
    )
