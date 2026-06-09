from jinja2 import Environment


environment = Environment()


def render_campaign_job(
    source: str,
    recipients: list[dict],
) -> list[str]:
    template = environment.from_string(
        source
    )

    return [
        template.render(
            recipient
        )
        for recipient in recipients
    ]
