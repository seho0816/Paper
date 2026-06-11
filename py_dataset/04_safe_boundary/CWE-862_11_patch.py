from flask import jsonify, request, abort, g

# Assume require_permission is defined elsewhere (e.g., in an authentication module)
# and populates g.user with the authenticated user object.
# Assume save_grade is defined elsewhere (e.g., in a service layer).


@require_permission("grades:update")
def update_grade(
    student_id: str,
):
    # CWE-862: Missing Authorization.
    # Add resource-level authorization to ensure the current authenticated user
    # (g.user) is authorized to update the grade for this specific student_id.
    # This check prevents users with a generic 'grades:update' permission
    # from modifying grades for students they are not authorized to manage.
    # We assume 'g.user' contains an attribute like 'managed_students', which
    # is a list or set of student_ids that the current user is permitted to manage.
    # This attribute would typically be populated by an upstream authentication/authorization
    # layer (e.g., by the require_permission decorator or another middleware)
    # based on the user's role and associated resources.
    if student_id not in g.user.managed_students:
        abort(403)  # Forbidden

    new_grade = request.json["grade"]
    save_grade(
        student_id,
        new_grade,
    )

    return jsonify({
        "updated": True,
    })
