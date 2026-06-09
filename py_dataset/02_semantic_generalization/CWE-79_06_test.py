from flask import Flask, request

app = Flask(__name__)


@app.post("/email/preview")
def preview_email():
    subject = request.form.get("subject", "")
    message = request.form.get("message", "")

    return (
        "<article>"
        f"<h1>{subject}</h1>"
        f"<div>{message}</div>"
        "</article>"
    )
