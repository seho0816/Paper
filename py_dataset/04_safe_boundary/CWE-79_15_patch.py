from flask import Response, request
from markupsafe import escape


def echo_message():
    message = request.args.get("message", "")

    # CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    # Although the content_type is 'text/plain', which mitigates typical HTML-based XSS,
    # it's best practice to sanitize or escape user input before reflecting it.
    # This prevents potential issues if the content_type were ever changed to 'text/html'
    # without updating the sanitization, or in scenarios with unusual client interpretations.
    safe_message = escape(message)

    return Response(
        safe_message,
        content_type="text/plain; charset=utf-8",
    )
