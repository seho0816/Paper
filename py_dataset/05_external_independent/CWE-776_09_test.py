from lxml import etree


def parse_saml_document(
    saml_xml: bytes,
):
    parser = etree.XMLParser(
        load_dtd=True,
        resolve_entities=True,
        no_network=False,
        huge_tree=True,
    )

    return etree.fromstring(
        saml_xml,
        parser,
    )
