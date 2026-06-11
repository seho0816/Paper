from flask import Response, request


def export_logs():
    # CWE-770: Allocation of Resources Without Limiting Size of Request
    # Define a reasonable maximum limit to prevent excessive resource allocation
    # and potential Denial of Service (DoS) due to memory or CPU exhaustion.
    MAX_LOG_EXPORT_LIMIT = 1000

    limit = int(
        request.args.get("limit", "100")
    )

    # Enforce the maximum limit to prevent an attacker from requesting an arbitrarily large number of logs.
    limit = min(limit, MAX_LOG_EXPORT_LIMIT)

    # Assuming query_logs is a defined function that fetches logs from a data source.
    rows = query_logs(limit=limit)
    lines = [
        ",".join(row)
        for row in rows
    ]

    return Response(
        "\n".join(lines),
        mimetype="text/csv",
    )
