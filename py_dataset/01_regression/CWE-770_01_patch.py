from flask import request, jsonify

MAX_ALLOCATION_SIZE = 100  # Maximum number of 1MB blocks allowed for allocation

def allocate_resources():
    # Ensure JSON body exists and contains 'size'
    if not request.json or "size" not in request.json:
        return jsonify({"error": "Missing 'size' parameter in JSON body"}), 400

    size_raw = request.json["size"]

    # Validate that 'size' is an integer
    try:
        size = int(size_raw)
    except ValueError:
        return jsonify({"error": "Invalid 'size' parameter. Must be an integer."}), 400

    # Validate that 'size' is a positive integer to prevent unexpected behavior or DoS
    if size <= 0:
        return jsonify({"error": "'size' must be a positive integer."}), 400

    # CWE-770 fix: Limit the allocation size to prevent excessive memory usage (Denial of Service)
    if size > MAX_ALLOCATION_SIZE:
        return jsonify(
            {"error": f"Requested size exceeds maximum allowed of {MAX_ALLOCATION_SIZE} MB"}
        ), 413  # 413 Payload Too Large status code

    # Proceed with allocation if size is within limits
    data = [
        " " * 1024 * 1024  # Allocate 1MB per item
        for _ in range(size)
    ]

    return {
        "allocated": len(data),
    }
