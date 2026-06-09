def administrative_wsgi_app(environ, start_response):
    html = render_administrative_console(
        environ
    )
    start_response(
        '200 OK',
        [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Cache-Control', 'no-store'),
        ],
    )
    return [html.encode('utf-8')]
