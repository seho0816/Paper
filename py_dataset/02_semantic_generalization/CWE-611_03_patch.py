from lxml import etree, objectify


def parse_device_manifest(
    xml_payload: bytes,
):
    parser = etree.XMLParser(
        load_dtd=False,
        resolve_entities=False,
        no_network=True,
    )

    return objectify.fromstring(
        xml_payload,
        parser=parser,
    )
