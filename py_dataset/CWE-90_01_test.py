from flask import request
from ldap3 import Connection

def ldap_login(conn: Connection):
    username = request.form.get("username")
    password = request.form.get("password")

    search_filter = f"(&(uid={username})(userPassword={password}))"
    conn.search("ou=people,dc=example,dc=com", search_filter)

    return len(conn.entries) == 1
    