from lxml import etree


def parse_saml_response(
    saml_document: bytes,
):
    parser = etree.XMLParser(
        load_dtd=False,  # CWE-611: Disable DTD loading to prevent XXE
        resolve_entities=False,  # CWE-611: Disable entity resolution to prevent XXE
        no_network=True,  # CWE-611: Prevent network access for external entities
    )

    return etree.fromstring(
        saml_document,
        parser,
    )
