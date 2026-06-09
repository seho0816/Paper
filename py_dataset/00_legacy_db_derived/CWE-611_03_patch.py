import io
import xml.sax


class PartnerXmlSaxReader:
    def parse(self, xml_text: str):
        parser = xml.sax.make_parser()
        # CWE-611: Disable external entity processing to prevent XXE vulnerabilities.
        # SAX parsers often default these to False, but explicit disabling is safer.
        parser.setFeature("http://xml.org/sax/features/external-general-entities", False)
        parser.setFeature("http://xml.org/sax/features/external-parameter-entities", False)

        source = xml.sax.xmlreader.InputSource()
        source.setByteStream(io.BytesIO(xml_text.encode("utf-8")))
        parser.parse(source)
        return parser
