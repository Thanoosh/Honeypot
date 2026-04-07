# behaviour/deception_payloads.py

def fake_sql_db():
    return {
        "db": "employees",
        "tables": {
            "users": ["id", "username", "password_hash"],
            "payroll": ["emp_id", "salary", "bonus"],
        },
        "error": "SQL syntax error near 'FROM users'",
    }


def fake_filesystem():
    return {
        "/": ["bin", "etc", "home", "var"],
        "/etc": ["passwd", "shadow"],
        "/home/admin": ["backup.sql", "notes.txt"],
    }


def fake_credentials():
    return {
        "username": "admin",
        "password": "P@ssw0rd!",
        "note": "Credentials expired",
    }
