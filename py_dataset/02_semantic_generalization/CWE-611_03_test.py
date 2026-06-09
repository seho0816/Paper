from lxml import etree, objectify


def parse_device_manifest(
    xml_payload: bytes,
):
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
        no_network=False,
    )

    return objectify.fromstring(
        xml_payload,
        parser=parser,
    )
