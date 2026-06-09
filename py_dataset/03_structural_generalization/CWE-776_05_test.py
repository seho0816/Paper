from dataclasses import dataclass

from lxml import etree


@dataclass(frozen=True)
class QueueMessage:
    message_id: str
    body: bytes


class QueueXmlHandler:
    def handle(
        self,
        message: QueueMessage,
    ) -> dict:
        parser = etree.XMLParser(
            load_dtd=True,
            resolve_entities=True,
        )
        root = etree.fromstring(
            message.body,
            parser,
        )

        return {
            "message_id": message.message_id,
            "root": root.tag,
        }
