import html

class PartnerLinkRenderer:
    def render_link(self, partner_name: str, partner_url: str) -> str:
        # CWE-1022 fix: rel="noopener noreferrer"로 reverse tabnapping 방지
        # + html.escape로 XSS 방지
        escaped_name = html.escape(partner_name)
        safe_url = partner_url
        if safe_url.lower().startswith(("javascript:", "data:")):
            safe_url = "#"
        escaped_url = html.escape(safe_url)
        return (
            f'<a class="partner-link" href="{escaped_url}" target="_blank" rel="noopener noreferrer">'
            f"{escaped_name}"
            "</a>"
        )


def render_partner_section(partners: list[dict[str, str]]) -> str:
    renderer = PartnerLinkRenderer()
    return "\n".join(
        renderer.render_link(partner["name"], partner["url"])
        for partner in partners
    )