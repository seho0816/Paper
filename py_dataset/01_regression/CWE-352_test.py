from flask import redirect, request


def change_email():
    if request.method == "POST":
        current_user.email = request.form.get("email", "")
        save_user(current_user)
        return redirect("/profile")

    return "method not allowed", 405
