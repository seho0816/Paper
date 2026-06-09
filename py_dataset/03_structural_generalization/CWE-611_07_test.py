from dataclasses import dataclass
from lxml import etree


@dataclass(frozen=True)
class SoapResponse:
    body: bytes


class SoapDecoder:
    def decode(
        self,
        response: SoapResponse,
    ):
        parser = etree.XMLParser(
            load_dtd=True,
            resolve_entities=True,
        )

        return etree.fromstring(
            response.body,
            parser,
        )


class PartnerClient:
    def __init__(self, decoder: SoapDecoder) -> None:
        self._decoder = decoder

    def read_result(self, endpoint: str):
        raw_response = fetch_partner_response(endpoint)
        return self._decoder.decode(
            SoapResponse(body=raw_response)
        )
