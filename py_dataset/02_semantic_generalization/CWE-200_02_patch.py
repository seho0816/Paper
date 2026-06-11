from fastapi import FastAPI

app = FastAPI()


# Assume employee_repository is defined elsewhere and provides Employee objects
# For example:
# class Employee:
#     def __init__(self, id, name, salary, bank_account):
#         self.id = id
#         self.name = name
#         self.salary = salary
#         self.bank_account = bank_account
#
# class EmployeeRepository:
#     def find_all(self):
#         return [
#             Employee(1, "Alice", 70000, "1234-5678"),
#             Employee(2, "Bob", 60000, "9876-5432"),
#         ]
#
# employee_repository = EmployeeRepository()


@app.get("/api/directory/employees")
async def list_employees() -> list[dict]:
    employees = employee_repository.find_all()

    return [
        {
            "employee_id": employee.id,
            "name": employee.name,
        }
        for employee in employees
    ]
