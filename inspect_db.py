"""Read-only local SQLite inspection for the class demonstration."""

from app.main import database, init_database


def main() -> None:
    init_database()
    with database() as connection:
        rows = connection.execute(
            "SELECT username, role, password_hash FROM users ORDER BY id"
        ).fetchall()
    if not rows:
        print("No accounts have been created yet.")
    for row in rows:
        print(f"Username: {row['username']} | Role: {row['role']}")
        print(f"Stored password_hash: {row['password_hash']}")
        print("-" * 36)


if __name__ == "__main__":
    main()

