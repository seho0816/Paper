class PayrollService:
    def GetPayslip(self, request, context):
        # CWE-566: Authorization Bypass Through User-Controlled SQL Query Elements
        # The original code only checked for 'id', allowing any user to potentially
        # view any payslip if they knew its ID.
        # To fix this, we must ensure that the requested payslip's 'employee_id'
        # matches the ID of the authenticated user making the request.
        # Assuming request.user_id holds the ID of the currently authenticated user.
        row = payroll_database.execute(
            'SELECT id, employee_id, gross_pay FROM payslips WHERE id = ? AND employee_id = ?',
            (request.payslip_id, request.user_id),
        ).fetchone()
        return {'id': row[0], 'employee_id': row[1], 'gross_pay': row[2]}
