from flask import jsonify


@require_permission("grades:update")
def update_grade(
    student_id: str,
):
    new_grade = request.json["grade"]
    save_grade(
        student_id,
        new_grade,
    )

    return jsonify({
        "updated": True,
    })
