import sqlite3

connection = sqlite3.connect(
    "database/agent.db"
)

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY,
    name TEXT,
    department TEXT
)
""")

cursor.execute("""
INSERT INTO employees
(name, department)
VALUES
('Alice', 'HR')
""")

cursor.execute("""
INSERT INTO employees
(name, department)
VALUES
('Bob', 'IT')
""")

cursor.execute("""
INSERT INTO employees
(name, department)
VALUES
('Charlie', 'Finance')
""")

connection.commit()

connection.close()

print("Database Created")