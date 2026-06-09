def create_email_subject(
    subject_template: str,
    account: dict,
) -> str:
    # CWE-134: Uncontrolled Format String
    # If 'subject_template' is user-controlled and 'account' contains sensitive data,
    # an attacker could craft 'subject_template' to extract sensitive information
    # from the 'account' dictionary (e.g., "{password}").

    # Fix: Filter the 'account' dictionary to only expose keys that are explicitly
    # considered safe for templating in an email subject. This prevents an attacker
    # from probing for sensitive keys within the 'account' dictionary via
    # 'subject_template'. The set of `allowed_keys` should be carefully defined
    # by the application based on what information is deemed safe to appear
    # in a subject line.

    # Example of commonly non-sensitive account information that might be
    # used in an email subject. This list should be defined based on
    # application requirements and data sensitivity.
    allowed_keys = ["username", "email", "first_name", "last_name", "id"]

    safe_account_data = {}
    for key in allowed_keys:
        if key in account:
            safe_account_data[key] = account[key]

    # Use the filtered dictionary for formatting.
    # Any format specifiers in 'subject_template' that refer to keys not present
    # in 'safe_account_data' will result in a KeyError, preventing accidental
    # exposure of unintended data or undefined behavior.
    return subject_template.format(
        **safe_account_data
    )
