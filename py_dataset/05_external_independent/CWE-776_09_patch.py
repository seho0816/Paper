from lxml import etree


def parse_saml_document(
    saml_xml: bytes,
):
    parser = etree.XMLParser(
        load_dtd=False,
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
    )

    return etree.fromstring(
        saml_xml,
        parser,
    )
