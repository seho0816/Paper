from lxml import etree


def parse_soap_response(
    response_body: bytes,
):
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
        huge_tree=True,
    )

    return etree.fromstring(
        response_body,
        parser,
    )
