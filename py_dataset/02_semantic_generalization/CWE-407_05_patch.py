def detect_forbidden_tags(
    submitted_tags: list[str],
    forbidden_tags: list[str],
) -> list[str]:
    matches = []

    for submitted in submitted_tags:
        # Pre-normalize the submitted tag once for efficiency and consistency.
        # This also ensures that if the submitted tag matches a forbidden tag,
        # the version added to `matches` is the normalized (and thus, safe) version.
        normalized_submitted = normalize_tag(submitted)
        for forbidden in forbidden_tags:
            # CWE-407 (Insufficient Protection Against Malicious Data):
            # If `normalize_tag` is used to sanitize or canonicalize data
            # to protect against malicious input, but the original (potentially
            # malicious) `submitted` tag is later used or returned, the protection
            # provided by `normalize_tag` is bypassed.
            # The fix ensures that only the protected, normalized version is
            # returned in the `matches` list.
            if normalized_submitted == normalize_tag(forbidden):
                # FIX: Append the normalized version of the submitted tag
                # to prevent the return of potentially malicious or malformed
                # data that `normalize_tag` was designed to mitigate.
                matches.append(normalized_submitted)

    return matches
