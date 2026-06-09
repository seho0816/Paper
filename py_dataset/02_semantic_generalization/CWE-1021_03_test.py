from flask import make_response


def payment_approval_page(html: str):
    response = make_response(html, 200)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Cache-Control'] = 'no-store'
    return response
