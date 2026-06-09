from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)

def parse_invoice_xml(xml_body):
    # CWE-611 fix: Disable external entity resolution (resolve_entities=False)
    # and DTD loading (load_dtd=False) to prevent XML External Entity (XXE) attacks.
    # Also added no_network=True to prevent the parser from making network requests,
    # which further mitigates XXE risks.
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    root = etree.fromstring(xml_body, parser)
    return root

@app.route("/invoice/xml", methods=["POST"])
def parse_xml():
    xml_body = request.data

    root = parse_invoice_xml(xml_body)

    return jsonify({
        "root": root.tag,
    })
