from flask import Flask, request
from markupsafe import escape # Import escape for XSS prevention

app = Flask(__name__)


@app.post("/email/preview")
def preview_email():
    subject = request.form.get("subject", "")
    message = request.form.get("message", "")

    # CWE-79: Cross-site Scripting (XSS) vulnerability fixed by escaping user input
    # before embedding it into the HTML response.
    return (
        "<article>"
        f"<h1>{escape(subject)}</h1>"
        f"<div>{escape(message)}</div>"
        "</article>"
    )
