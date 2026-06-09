import defusedxml.minidom


def parse_uploaded_xml(
    xml_text: str,
):
    return defusedxml.minidom.parseString(
        xml_text,
    )
