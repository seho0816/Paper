from flask import Flask, request, redirect

app = Flask(__name__)

user_settings = {
    "email_notification": True
}

@app.route("/settings/email", methods=["POST"])
def update_email_setting():
    enabled = request.form.get("enabled")

    user_settings["email_notification"] = enabled == "true"

    return redirect("/settings")