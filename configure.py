import importlib
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
from getpass import getpass
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "Brain" / "VectorOneBackend"
ENV_FILE = BACKEND / ".env"
ENV_TEMPLATE = BACKEND / ".env.example"
VENV = BACKEND / "venv"


def prompt_for_env() -> bool:
    if ENV_FILE.exists():
        answer = input(f"{ENV_FILE.relative_to(ROOT)} already exists. Overwrite it? [y/N]: ")
        return answer.strip().lower() in {"y", "yes"}
    return True


def write_env_file() -> None:
    template = ENV_TEMPLATE.read_text(encoding="utf-8").splitlines()
    values = {
        "VIRUSTOTAL_API_KEY": input("VirusTotal API key (press Enter to skip): ").strip(),
        "ABUSE_CH_API_KEY": input("Abuse.ch API key (press Enter to skip): ").strip(),
        "VECTORONE_AGENT_TOKEN": secrets.token_hex(32),
    }

    def format_value(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    written = set()
    output = []
    for line in template:
        key, separator, _ = line.partition("=")
        if separator and key in values:
            output.append(f"{key}={format_value(values[key])}")
            written.add(key)
        else:
            output.append(line)
    for key, value in values.items():
        if key not in written:
            output.append(f"{key}={format_value(value)}")

    ENV_FILE.write_text("\n".join(output) + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except OSError:
        if os.name != "nt":
            raise
    print(f"Wrote {ENV_FILE.relative_to(ROOT)}.")


def run_step(label: str, command: list[str], cwd: Path) -> None:
    print(f"\n{label}...")
    print(f"> {' '.join(command)}")
    subprocess.run(command, cwd=cwd, check=True)


def create_first_analyst() -> bool:
    answer = input("Would you like to create your first analyst account now? (Y/n): ").strip().lower()
    if answer in {"n", "no"}:
        return False

    if answer and answer not in {"y", "yes", ""}:
        print("Assuming yes. Continuing with analyst setup.")

    security_path = BACKEND / "security.py"
    if not security_path.is_file():
        print(f"Could not find {security_path.relative_to(ROOT)}.", file=sys.stderr)
        return False

    sys.path.insert(0, str(BACKEND))
    security = importlib.import_module("security")
    create_analyst = security.create_analyst
    initialize_auth_database = security.initialize_auth_database
    db_path = BACKEND / "vectorone_brain.db"

    initialize_auth_database(db_path)
    while True:
        email = input("Analyst email: ").strip()
        if email and "@" in email:
            break
        print("A valid email address is required.")

    full_name = input("Analyst full name: ").strip()
    company_name = input("Company name: ").strip()

    while True:
        password = getpass("Password (minimum 12 characters): ")
        if len(password) < 12:
            print("Password must be at least 12 characters long.")
            continue
        confirmation = getpass("Confirm password: ")
        if password != confirmation:
            print("Passwords do not match. Please try again.")
            continue
        break

    try:
        create_analyst(db_path, email, password, full_name, company_name)
    except (ValueError, sqlite3.IntegrityError) as exc:
        print(f"Could not create analyst account: {exc}", file=sys.stderr)
        return False

    print(f"Created analyst account for {email}.")
    print("You can now sign in to the React Console with this account.")
    return True


def main() -> int:
    if not ENV_TEMPLATE.is_file():
        print(f"Configuration template not found: {ENV_TEMPLATE}", file=sys.stderr)
        return 1

    try:
        if prompt_for_env():
            write_env_file()
        else:
            print("Keeping the existing .env file.")

        if not VENV.exists():
            run_step("Creating the Brain virtual environment", [sys.executable, "-m", "venv", str(VENV)], ROOT)

        venv_python = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run_step(
            "Installing Brain dependencies",
            [str(venv_python), "-m", "pip", "install", "-r", str(BACKEND / "requirements.txt")],
            ROOT,
        )

        npm = shutil.which("npm")
        if npm is None:
            raise FileNotFoundError("npm was not found. Install Node.js and npm, then run configure.py again.")
        run_step("Installing Console dependencies", [npm, "install"], ROOT / "Console")

        dotnet = shutil.which("dotnet")
        if dotnet is None:
            raise FileNotFoundError(".NET SDK was not found. Install the .NET 8 SDK, then run configure.py again.")
        run_step(
            "Restoring Agent packages",
            [dotnet, "restore", str(ROOT / "Agent" / "VectorOne" / "VectorOne.csproj")],
            ROOT,
        )

        create_first_analyst()
    except subprocess.CalledProcessError as error:
        print(f"Setup step failed with exit code {error.returncode}.", file=sys.stderr)
        return error.returncode or 1
    except (OSError, EOFError, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            print("\nSetup interrupted.", file=sys.stderr)
        elif isinstance(error, EOFError):
            print("\nSetup input ended unexpectedly.", file=sys.stderr)
        else:
            print(f"Setup failed: {error}", file=sys.stderr)
        return 1

    print("\nVectorOne setup is complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
