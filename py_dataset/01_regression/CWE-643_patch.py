from lxml import etree


TEAMS = etree.fromstring(
    b"<teams></teams>"
)


def find_team_members(
    team_name: str,
) -> list[str]:
    expression = (
        "/teams/team[name=$team_name_var]/members/member/name/text()"
    )

    return TEAMS.xpath(
        expression, team_name_var=team_name
    )
