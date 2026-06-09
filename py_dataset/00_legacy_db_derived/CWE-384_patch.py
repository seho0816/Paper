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

    # CWE-384 (Session Fixation) Vulnerability:
    # The application allows a user-supplied session identifier-like value ("sid")
    # to be stored directly in the session. An attacker could pre-set this value
    # for a victim. If this "sid" were later used to identify the authenticated session
    # or fetch user-specific data, the attacker might be able to hijack the victim's session
    # after they log in. To fix this, we remove the logic that accepts and stores
    # a user-supplied "sid" in the session.
    # if supplied_session:
    #     session["sid"] = supplied_session

    return redirect("/login/form")

@app.route("/login/form")
def login_form():
    return jsonify({
        "message": "show login form",
        "sid": session.get("sid"),
    })
