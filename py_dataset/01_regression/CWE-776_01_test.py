from xml.dom import minidom


def parse_uploaded_xml(
    xml_text: str,
):
    return minidom.parseString(
        xml_text,
    )
