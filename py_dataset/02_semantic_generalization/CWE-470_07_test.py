def run_report_action(
    action_name: str,
):
    def rebuild():
        return rebuild_report_index()

    def purge():
        return purge_report_cache()

    selected = locals()[
        action_name
    ]

    return selected()
