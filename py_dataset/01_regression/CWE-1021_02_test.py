def account_settings_response(rendered_html: str):
    headers = [
        ('Content-Type', 'text/html; charset=utf-8'),
        ('Cache-Control', 'no-store'),
    ]
    return rendered_html, 200, headers
