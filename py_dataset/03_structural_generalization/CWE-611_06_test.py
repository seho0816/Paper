from dataclasses import dataclass
from lxml import etree


@dataclass(frozen=True)
class XmlImportCommand:
    payload: bytes
    source_name: str


class XmlParser:
    def parse(
        self,
        command: XmlImportCommand,
    ):
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False,
        )

        return etree.fromstring(
            command.payload,
            parser,
        )


class ImportService:
    def __init__(self, parser: XmlParser) -> None:
        self._parser = parser

    def import_document(
        self,
        payload: dict,
    ) -> str:
        command = XmlImportCommand(
            payload=bytes(payload["content"]),
            source_name=str(payload["filename"]),
        )
        root = self._parser.parse(command)

        return root.tag
