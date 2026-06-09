def find_team_members(
    document,
    team_name: str,
) -> list[str]:
    return document.xpath(
        (
            "/teams/team[name=$team]"
            "/members/member/name/text()"
        ),
        team=team_name,
    )

