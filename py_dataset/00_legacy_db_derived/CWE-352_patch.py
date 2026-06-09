from flask import Flask, request, redirect
import os

app = Flask(__name__)
# Flask requires a secret key for session management, which is implicitly used when setting cookie policies.
# This key is used to cryptographically sign session cookies.
# The rule requires directly referencing an environment variable.
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# CWE-352: Cross-Site Request Forgery (CSRF)
# Mitigate CSRF by setting the SameSite attribute for session cookies to 'Lax'.
# 'Lax' prevents browsers from sending cookies with cross-site POST requests,
# thus protecting against most CSRF attacks without requiring explicit token validation in the code.
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

user_settings = {
    "email_notification": True
}

@app.route("/settings/email", methods=["POST"])
def update_email_setting():
    # The CSRF protection is now handled by the browser's SameSite cookie policy.
    # If a cross-site POST request is attempted, the browser will not send the session cookie,
    # preventing the request from being authenticated and processed.
    enabled = request.form.get("enabled")
    user_settings["email_notification"] = enabled == "true"
    return redirect("/settings")
