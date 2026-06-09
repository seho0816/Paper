from flask import Response, request


def export_logs():
    limit = int(
        request.args.get("limit", "100")
    )
    rows = query_logs(limit=limit)
    lines = [
        ",".join(row)
        for row in rows
    ]

    return Response(
        "\n".join(lines),
        mimetype="text/csv",
    )
