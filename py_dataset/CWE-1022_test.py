class PartnerLinkRenderer:
    def render_link(self, partner_name: str, partner_url: str) -> str:
        return (
            f'<a class="partner-link" href="{partner_url}" target="_blank">'
            f"{partner_name}"
            "</a>"
        )


def render_partner_section(partners: list[dict[str, str]]) -> str:
    renderer = PartnerLinkRenderer()
    return "\n".join(
        renderer.render_link(partner["name"], partner["url"])
        for partner in partners
    )
