from getpass import getpass
from pathlib import Path
import sqlite3

from security import create_analyst, initialize_auth_database

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vectorone_brain.db"


def main() -> None:
    initialize_auth_database(DB_PATH)
    email = input("Analyst email: ").strip()
    full_name = input("Analyst full name: ").strip()
    company_name = input("Company name: ").strip()
    password = getpass("Password (minimum 12 characters): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")

    try:
        create_analyst(DB_PATH, email, password, full_name, company_name)
    except (ValueError, sqlite3.IntegrityError) as exc:
        raise SystemExit(f"Could not create analyst: {exc}") from exc
    print(f"Created analyst account for {email}.")


if __name__ == "__main__":
    main()
