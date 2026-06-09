from lxml import etree


USERS = etree.fromstring(
    b"<users></users>"
)


def xml_login(
    username: str,
    password: str,
) -> bool:
    expression = (
        f"//user[name='{username}' "
        f"and password='{password}']"
    )

    return bool(
        USERS.xpath(
            expression
        )
    )
