from defusedxml import minidom


def parse_profile(
    xml_text: str,
):
    # CWE-611 (Improper Restriction of XML External Entity Reference) is mitigated
    # by using `defusedxml.minidom`. This library is designed to safely parse XML
    # by disabling external entity processing and preventing XML-related denial-of-service
    # attacks (e.g., Billion Laughs, Quadratic Blowup, XXE).
    # Therefore, the existing code is already considered safe against CWE-611.
    return minidom.parseString(
        xml_text,
    )
