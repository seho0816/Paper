from flask import Flask, request, session, redirect, jsonify

app = Flask(__name__)
app.secret_key = "dev-secret"

def remember_tracking_value(value):
    session["tracking"] = value

@app.route("/login")
def login_page():
    supplied_session = request.args.get("sid")
    tracking = request.args.get("tracking")

    if tracking:
        remember_tracking_value(tracking)

    if supplied_session:
        session["sid"] = supplied_session

    return redirect("/login/form")

@app.route("/login/form")
def login_form():
    return jsonify({
        "message": "show login form",
        "sid": session.get("sid"),
    })
