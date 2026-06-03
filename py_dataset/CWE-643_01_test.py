from flask import request
from lxml import etree

doc = etree.fromstring(b"<users></users>")

def xml_login():
    username = request.form.get("username")
    password = request.form.get("password")

    xpath = f"//user[name='{username}' and password='{password}']"
    matches = doc.xpath(xpath)

    return len(matches) == 1
