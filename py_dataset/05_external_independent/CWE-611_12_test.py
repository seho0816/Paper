from lxml import etree


def parse_saml_response(
    saml_document: bytes,
):
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
        no_network=False,
    )

    return etree.fromstring(
        saml_document,
        parser,
    )
