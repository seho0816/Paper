from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route('/profile/favorites', methods=['POST'])
def add_to_favorites():
    parser = etree.XMLParser(resolve_entities=True)
    favorite = etree.fromstring(request.data, parser)
    add_to_favorites(favorite)