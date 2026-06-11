# CWE-776: Bandit(B320) 우회 및 XXE 원천 차단을 위해 안전한 defusedxml 파서 사용
import defusedxml.lxml as etree

def parse_partner_xml(
    xml_body: bytes,
):
    parser = etree.XMLParser(
        resolve_entities=False,
    )

    return etree.fromstring(
        xml_body,
        parser,
    )