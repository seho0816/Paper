import time
from flask import redirect, url_for, flash
from flask_login import current_user, login_user


# Assume app, LoginForm, User, render_template are defined and imported elsewhere
# For example:
# from flask import Flask, render_template, redirect, url_for, flash, request
# from flask_login import LoginManager, login_user, current_user, UserMixin
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired
#
# # Mock classes to make the code runnable for testing, not part of the required output
# class User(UserMixin):
#     def __init__(self, id, username, password):
#         self.id = id
#         self.username = username
#         self.password = password # In real app, this would be a hash
#         self.failed_login_attempts = 0
#         self.last_failed_attempt_time = 0.0
#
#     def get_id(self):
#         return str(self.id)
#
#     def check_password(self, password):
#         return self.password == password
#
#     @classmethod
#     def query(cls):
#         class _UserQuery:
#             _users_db = {
#                 "testuser": User(1, "testuser", "password123"),
#                 "admin": User(2, "admin", "adminpass")
#             }
#             def filter_by(self, username):
#                 class _FilterResult:
#                     def first(self):
#                         return _UserQuery._users_db.get(username)
#                 return _FilterResult()
#         return _UserQuery()
#
# class LoginForm(FlaskForm):
#     username = StringField("Username", validators=[DataRequired()])
#     password = PasswordField("Password", validators=[DataRequired()])
#     submit = SubmitField("Login")
#
# app = Flask(__name__)
# app.config["SECRET_KEY"] = "super_secret_key"
# login_manager = LoginManager()
# login_manager.init_app(app)
#
# @login_manager.user_loader
# def load_user(user_id):
#     for user in User.query()._users_db.values():
#         if user.id == int(user_id):
#             return user
#     return None
#
# def render_template(template_name, **context):
#     return f"Rendering {template_name} with {context}"

@app.route("/login", methods=["GET", "POST"])
def login():
   if current_user.is_authenticated:
       return redirect(url_for("index"))

   form = LoginForm()
   if form.validate_on_submit():
       username = form.username.data
       user = User.query.filter_by(username=username).first()

       # Constants for the lockout policy
       MAX_FAILED_ATTEMPTS = 5
       LOCKOUT_DURATION_SECONDS = 300 # 5 minutes

       # --- CWE-307 Fix Start ---
       # Initialize security attributes on the user object if they don't exist.
       # In a real application, these would be proper model fields.
       if user:
           if not hasattr(user, 'failed_login_attempts'):
               user.failed_login_attempts = 0
           if not hasattr(user, 'last_failed_attempt_time'):
               user.last_failed_attempt_time = 0.0 # Unix timestamp

           # Check for account lockout before processing login attempt
           if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
               time_since_last_attempt = time.time() - user.last_failed_attempt_time
               if time_since_last_attempt < LOCKOUT_DURATION_SECONDS:
                   remaining_time = int(LOCKOUT_DURATION_SECONDS - time_since_last_attempt)
                   flash(f"Account locked due to too many failed attempts. Please try again in {remaining_time} seconds.")
                   return redirect(url_for("login"))
               else:
                   # Lockout period has passed, reset attempts
                   user.failed_login_attempts = 0
                   user.last_failed_attempt_time = 0.0

       # Authenticate the user
       if user is None or not user.check_password(form.password.data):
           # Failed login attempt
           if user: # Only track attempts for existing users
               user.failed_login_attempts += 1
               user.last_failed_attempt_time = time.time()
               # Assume ORM persists changes to the user object (e.g., db.session.commit())

           flash("Invalid username or password")
           return redirect(url_for("login"))
       else:
           # Successful login
           if user:
               # Reset failed attempts on successful login
               user.failed_login_attempts = 0
               user.last_failed_attempt_time = 0.0
               # Assume ORM persists changes to the user object (e.g., db.session.commit())

           login_user(user)
           return redirect(url_for("user_page"))
       # --- CWE-307 Fix End ---

   return render_template("login.html", form = form)
