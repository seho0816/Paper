from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

@login_required
def change_password(request):
    if request.method == "POST":
        new_value = request.POST["new_password"]
        repeated = request.POST["confirm_password"]
        if new_value == repeated:
            request.user.set_password(new_value)
            request.user.save(update_fields=["password"])
            return redirect("profile")
    return render_password_form(request)
