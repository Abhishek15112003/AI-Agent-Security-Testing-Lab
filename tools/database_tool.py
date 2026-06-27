import sqlite3
from logs.logger import log_activity

DATABASE = "database/agent.db"

def query_database():

    log_activity(
        "Employee Database Accessed"
    )

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM employees"
    )

    records = cursor.fetchall()

    connection.close()

    output = []

    for employee in records:

        output.append(
            f"{employee[1]} ({employee[2]})"
        )

    return "\n".join(output)