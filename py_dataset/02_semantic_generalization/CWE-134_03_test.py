def create_email_subject(
    subject_template: str,
    account: dict,
) -> str:
    return subject_template.format(
        **account
    )
