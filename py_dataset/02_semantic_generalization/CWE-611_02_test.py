import io
import xml.sax
from xml.sax.handler import feature_external_ges, feature_external_pes


def parse_partner_xml(
    xml_text: str,
) -> None:
    parser = xml.sax.make_parser()
    parser.setFeature(
        feature_external_ges,
        True,
    )
    parser.setFeature(
        feature_external_pes,
        True,
    )
    parser.parse(
        io.StringIO(xml_text)
    )
