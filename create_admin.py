"""Create an Admin account locally. Credentials are prompted, never in CLI arguments."""

import getpass
import sqlite3

from app.main import database, hash_password, init_database, validate_new_account


def main() -> None:
    init_database()
    print("Create a local AuthGuard admin (not available through registration).")
    username = input("Admin username: ")
    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match. Nothing was created.")
        return
    try:
        username = validate_new_account(username, password)
    except ValueError as error:
        print(f"Cannot create admin: {error}")
        return
    try:
        with database() as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                (username, hash_password(password)),
            )
    except sqlite3.IntegrityError:
        print("Username unavailable. Nothing was created.")
        return
    print(f"Admin account '{username}' created.")


if __name__ == "__main__":
    main()

