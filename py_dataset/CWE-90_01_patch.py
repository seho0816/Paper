from flask import request
from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars

def ldap_login(conn: Connection):
    username = request.form.get("username")
    password = request.form.get("password")

    # Escape special characters in username and password to prevent LDAP injection
    # If username or password is None, escape_filter_chars will handle it by returning an empty string or the input itself if not a string.
    # We add a check to ensure it's treated as an empty string for the filter if None.
    escaped_username = escape_filter_chars(username) if username is not None else ""
    escaped_password = escape_filter_chars(password) if password is not None else ""

    search_filter = f"(&(uid={escaped_username})(userPassword={escaped_password}))"
    conn.search("ou=people,dc=example,dc=com", search_filter)

    return len(conn.entries) == 1
