def find_directory_user(
    ldap_connection,
    request,
):
    employee_id = request.GET.get(
        "employee_id",
        "",
    )
    expression = (
        "(employeeNumber="
        + employee_id
        + ")"
    )
    ldap_connection.search(
        EMPLOYEE_BASE,
        expression,
    )

    return ldap_connection.entries
