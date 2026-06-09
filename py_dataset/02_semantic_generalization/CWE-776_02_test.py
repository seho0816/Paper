import io
import xml.sax
from xml.sax.handler import feature_external_ges


def parse_xml(
    xml_text: str,
) -> None:
    parser = xml.sax.make_parser()
    parser.setFeature(
        feature_external_ges,
        True,
    )
    parser.parse(
        io.StringIO(xml_text)
    )
