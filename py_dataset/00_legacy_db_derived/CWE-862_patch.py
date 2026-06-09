from flask import Flask, request, jsonify
import os
import hmac

app = Flask(__name__)

grades = {
    "20223948": {
        "student_name": "Ezra",
        "subject": "Statistics",
        "grade": "F"
    }
}

@app.route("/grades", methods=["PATCH"])
def update_grade():
    # CWE-862 Fix: Add Authorization Check
    # This implementation expects an API key in the 'X-API-KEY' header
    # and compares it to a secret stored in the 'FLASK_API_KEY' environment variable.
    expected_api_key = os.environ.get("FLASK_API_KEY")
    provided_api_key = request.headers.get("X-API-KEY")

    if not expected_api_key:
        # If no API key is configured on the server, deny access to prevent insecure operations.
        # A 500 Internal Server Error is returned as it's a server-side configuration issue.
        return jsonify({"message": "Server API key not configured."}), 500

    # Ensure a key was provided and perform a constant-time comparison to prevent timing attacks.
    if not provided_api_key or not hmac.compare_digest(
        expected_api_key.encode('utf-8'),
        provided_api_key.encode('utf-8')
    ):
        return jsonify({"message": "Unauthorized"}), 403

    # Original vulnerable logic follows, now protected by authorization.
    student_id = request.json.get("studentID")
    subject_id = request.json.get("subjectID")
    new_grade = request.json.get("grade")

    # Basic check for student_id existence to prevent KeyError
    if student_id not in grades:
        return jsonify({"message": "Student not found."}), 404

    grades[student_id]["grade"] = new_grade

    return jsonify({
        "message": "grade updated",
        "studentID": student_id,
        "subjectID": subject_id,
        "grade": grades[student_id]["grade"]
    })
