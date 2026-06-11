from lxml import etree


def parse_soap_response(
    response_body: bytes,
):
    # CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
    # To mitigate XML Entity Expansion (e.g., XML bomb) and XXE attacks,
    # load_dtd and resolve_entities should be set to False, and huge_tree should be removed or set to False.
    # By default, lxml provides reasonable safeguards when huge_tree is not set to True.
    parser = etree.XMLParser(
        load_dtd=False,
        resolve_entities=False,
        # huge_tree=True is removed to prevent unbounded resource allocation
        # and re-enable default tree depth and node size restrictions.
    )

    return etree.fromstring(
        response_body,
        parser,
    )
