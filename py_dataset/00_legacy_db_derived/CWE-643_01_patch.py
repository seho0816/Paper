from flask import request
from lxml import etree

doc = etree.fromstring(b"<users></users>")

def xml_login():
    username = request.form.get("username")
    password = request.form.get("password")

    # CWE-643 fix: Use parameterized XPath queries to prevent XPath injection.
    # User-supplied inputs (username, password) are passed as variables
    # rather than directly interpolated into the XPath string.
    xpath_template = "//user[name=$username_val and password=$password_val]"
    matches = doc.xpath(xpath_template, username_val=username, password_val=password)

    return len(matches) == 1
