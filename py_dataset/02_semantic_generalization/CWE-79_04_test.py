from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.get("/welcome")
def welcome():
    nickname = request.args.get("nickname", "")
    template = (
        "<html><body><div>"
        + nickname
        + "</div></body></html>"
    )

    return render_template_string(template)
