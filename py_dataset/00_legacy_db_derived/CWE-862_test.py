from flask import Flask, request, jsonify

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
    student_id = request.json.get("studentID")
    subject_id = request.json.get("subjectID")
    new_grade = request.json.get("grade")
    grades[student_id]["grade"] = new_grade

    return jsonify({
        "message": "grade updated",
        "studentID": student_id,
        "subjectID": subject_id,
        "grade": grades[student_id]["grade"]
    })