import ldap.filter

def find_directory_user(
    ldap_connection,
    request,
):
    employee_id = request.GET.get(
        "employee_id",
        "",
    )
    escaped_employee_id = ldap.filter.escape_filter_chars(employee_id)
    expression = (
        "(employeeNumber="
        + escaped_employee_id
        + ")"
    )
    ldap_connection.search(
        EMPLOYEE_BASE,
        expression,
    )

    return ldap_connection.entries
