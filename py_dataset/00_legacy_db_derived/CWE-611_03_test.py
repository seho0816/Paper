import io
import xml.sax


class PartnerXmlSaxReader:
    def parse(self, xml_text: str):
        parser = xml.sax.make_parser()
        parser.setFeature("http://xml.org/sax/features/external-general-entities", True)
        parser.setFeature("http://xml.org/sax/features/external-parameter-entities", True)

        source = xml.sax.xmlreader.InputSource()
        source.setByteStream(io.BytesIO(xml_text.encode("utf-8")))
        parser.parse(source)
        return parser
