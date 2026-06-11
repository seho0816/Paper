from lxml import etree


USERS = etree.fromstring(
    b"<users></users>"
)


def xml_login(
    username: str,
    password: str,
) -> bool:
    expression = (
        "//user[name=$username "
        "and password=$password]"
    )

    return bool(
        USERS.xpath(
            expression,
            username=username,
            password=password,
        )
    )
