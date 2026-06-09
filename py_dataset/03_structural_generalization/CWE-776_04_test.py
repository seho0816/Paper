from dataclasses import dataclass

from lxml import etree


@dataclass(frozen=True)
class XmlImport:
    payload: bytes
    filename: str


class XmlReader:
    def read(
        self,
        request: XmlImport,
    ):
        parser = etree.XMLParser(
            load_dtd=True,
            resolve_entities=True,
            huge_tree=True,
        )

        return etree.fromstring(
            request.payload,
            parser,
        )


class ImportService:
    def __init__(
        self,
        reader: XmlReader,
    ) -> None:
        self._reader = reader

    def import_file(
        self,
        request: XmlImport,
    ) -> str:
        root = self._reader.read(
            request,
        )

        return root.tag
