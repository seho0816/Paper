def list_user_files(
    current_user_id: str,
) -> list[str]:
    visible_files = file_repository.find_visible_to_user(
        current_user_id
    )
    return [
        file_record['display_name']
        for file_record in visible_files
    ]

