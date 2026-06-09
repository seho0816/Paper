def get_information():
    
    dn = request.args['dn']
    jediTypeRequest = request.args['jediType']
    # here the problem lies
    ldapQuery = f"(|(jediType={jediTypeRequest})(&(cloneWars=yes)(alive=yes)))"

    connection = ldap.initialize("ldap://127.0.0.1:389")
    results = connection.search_s(dn, ldap.SCOPE_SUBTREE, ldapQuery)

    return results