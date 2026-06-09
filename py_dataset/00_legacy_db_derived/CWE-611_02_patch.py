from flask import Flask, request, jsonify
from defusedxml.dom import minidom

app = Flask(__name__)

def extract_root_name(xml_text):
    doc = minidom.parseString(xml_text)
    return doc.documentElement.tagName

@app.route("/invoice/read", methods=["POST"])
def read_invoice_xml():
    xml_text = request.data.decode("utf-8")

    root_name = extract_root_name(xml_text)

    return jsonify({
        "root": root_name,
    })
