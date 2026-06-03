from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)

def parse_invoice_xml(xml_body):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    root = etree.fromstring(xml_body, parser)
    return root

@app.route("/invoice/xml", methods=["POST"])
def parse_xml():
    xml_body = request.data

    root = parse_invoice_xml(xml_body)

    return jsonify({
        "root": root.tag,
    })
