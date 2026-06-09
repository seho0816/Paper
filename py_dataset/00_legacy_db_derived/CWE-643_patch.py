from flask import Flask, request, abort
from lxml import etree

app = Flask(__name__)

with open("/var/tmp/export.xml", "r") as file:
    xml = file.read()

doc = etree.fromstring(xml)

@app.route("/showteam", methods=["GET"])
def show_team():
    team_name = request.args.get("team")
    if team_name is None:
        abort(400, description="team name missing")
    try:
        # CWE-643 fix: Use XPath variables to prevent XPath Injection
        # The user-supplied team_name is passed as a variable, not concatenated into the query string.
        nodes = doc.xpath(
            "/teams/team[name=$teamName]/members/member/name/text()",
            teamName=team_name
        )
        response_html = "<ul>"
        for node in nodes:
            response_html += "<li>" + node + "</li>"
        response_html += "</ul>"
        return response_html
    except etree.XPathEvalError as e:
        abort(500, description="Failed to query XML: " + str(e))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
