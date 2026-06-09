from lxml import etree


TEAMS = etree.fromstring(
    b"<teams></teams>"
)


def find_team_members(
    team_name: str,
) -> list[str]:
    expression = (
        "/teams/team[name='"
        + team_name
        + "']/members/member/name/text()"
    )

    return TEAMS.xpath(
        expression
    )
