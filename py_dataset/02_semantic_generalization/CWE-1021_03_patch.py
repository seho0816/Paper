from flask import make_response
from bleach import clean


def payment_approval_page(html: str):
    sanitized_html = clean(html)
    response = make_response(sanitized_html, 200)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Cache-Control'] = 'no-store'
    return response
