from fastapi import FastAPI

app = FastAPI()


@app.get("/api/directory/employees")
async def list_employees() -> list[dict]:
    employees = employee_repository.find_all()

    return [
        {
            "employee_id": employee.id,
            "name": employee.name,
            "salary": employee.salary,
            "bank_account": employee.bank_account,
        }
        for employee in employees
    ]
