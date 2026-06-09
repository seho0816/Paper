import ldap
import ldap.filter
from flask import request # Assuming 'request' object comes from Flask

def get_information():
    
    dn = request.args['dn']
    jediTypeRequest = request.args['jediType']
    
    # CWE-90 fix: Escape special characters in the user-provided input
    # before constructing the LDAP query to prevent LDAP injection.
    # ldap.filter.escape_filter_chars handles characters that have special meaning in LDAP filters.
    escaped_jediTypeRequest = ldap.filter.escape_filter_chars(jediTypeRequest)
    
    ldapQuery = f"(|(jediType={escaped_jediTypeRequest})(&(cloneWars=yes)(alive=yes)))"

    connection = ldap.initialize("ldap://127.0.0.1:389")
    results = connection.search_s(dn, ldap.SCOPE_SUBTREE, ldapQuery)

    return results
