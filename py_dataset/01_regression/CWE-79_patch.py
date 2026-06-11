from flask import Flask, request, make_response
from markupsafe import escape

app = Flask(__name__)
messages: list[str] = []


@app.route("/chat", methods=["GET", "POST"])
def chat():
    if request.method == "POST":
        messages.append(request.form.get("message", ""))

    body = "<html><body><h1>Chat</h1>"
    for message in messages:
        body += "<p>" + escape(message) + "</p>"
    body += "</body></html>"

    return make_response(body)
