def detect_forbidden_tags(
    submitted_tags: list[str],
    forbidden_tags: list[str],
) -> list[str]:
    matches = []

    for submitted in submitted_tags:
        for forbidden in forbidden_tags:
            if normalize_tag(
                submitted
            ) == normalize_tag(
                forbidden
            ):
                matches.append(
                    submitted
                )

    return matches
