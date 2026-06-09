from lxml import etree


def normalize_feed(
    feed_xml: bytes,
) -> bytes:
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
    )
    root = etree.fromstring(
        feed_xml,
        parser,
    )

    return etree.tostring(root)
