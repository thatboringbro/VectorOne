import argparse
import json
import os
import signal
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LOCK_FILE = ROOT / ".vectorone.lock"
BACKEND = ROOT / "Brain" / "VectorOneBackend"
CONSOLE = ROOT / "Console"
AGENT_PROJECT = ROOT / "Agent" / "VectorOne" / "VectorOne.csproj"
VENV_PYTHON = BACKEND / ("venv/Scripts/python.exe" if os.name == "nt" else "venv/bin/python")
SHUTDOWN_TIMEOUT = 5


def has_analyst_accounts() -> bool:
    db_path = BACKEND / "vectorone_brain.db"
    if not db_path.is_file():
        return False

    with sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True) as connection:
        has_analysts_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'analysts'"
        ).fetchone()
        if has_analysts_table is None:
            return False
        return connection.execute("SELECT EXISTS (SELECT 1 FROM analysts LIMIT 1)").fetchone()[0] == 1


def process_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def read_lock() -> dict[str, int]:
    try:
        content = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read {LOCK_FILE.name}: {error}") from error
    if not isinstance(content, dict) or any(
        not isinstance(name, str) or isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0
        for name, pid in content.items()
    ):
        raise ValueError(f"{LOCK_FILE.name} has an invalid format.")
    return content


def stop_pid(pid: int, name: str) -> bool:
    if not process_is_running(pid):
        print(f"{name} (PID {pid}) is not running.")
        return True

    if os.name == "nt":
        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as error:
            print(f"Could not run taskkill for {name} (PID {pid}): {error}", file=sys.stderr)
            return False
        if result.returncode != 0 and process_is_running(pid):
            print(f"Could not stop {name} (PID {pid}): {result.stderr.strip() or result.stdout.strip()}", file=sys.stderr)
            return False
        return True

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except PermissionError:
        print(f"Permission denied while stopping {name} (PID {pid}).", file=sys.stderr)
        return False

    deadline = time.monotonic() + SHUTDOWN_TIMEOUT
    while process_is_running(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    if not process_is_running(pid):
        return True

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        print(f"Permission denied while force-stopping {name} (PID {pid}).", file=sys.stderr)
        return False
    return True


def terminate_child(process: subprocess.Popen, name: str) -> None:
    if process.poll() is not None:
        return

    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.send_signal(signal.SIGTERM)
        process.wait(timeout=SHUTDOWN_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as error:
                print(f"Could not force-stop {name} (PID {process.pid}): {error}", file=sys.stderr)
        else:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait()
        except OSError as error:
            print(f"Could not wait for {name} (PID {process.pid}): {error}", file=sys.stderr)
    print(f"Stopped {name} (PID {process.pid}).")


def start() -> int:
    if LOCK_FILE.exists():
        print(f"{LOCK_FILE.name} already exists. Run `python vector_one.py status` or `stop` first.", file=sys.stderr)
        return 1

    try:
        if not has_analyst_accounts():
            print(
                "Reminder: no analyst accounts found. Create one with `python configure.py` "
                "or `python Brain/VectorOneBackend/create_analyst.py` before signing in to the Console."
            )
    except sqlite3.Error as error:
        print(f"Could not check for analyst accounts: {error}", file=sys.stderr)
        return 1

    npm = shutil.which("npm")
    dotnet = shutil.which("dotnet")
    if npm is None or dotnet is None:
        missing = [name for name, path in (("npm", npm), ("dotnet", dotnet)) if path is None]
        print(f"Required command not found: {', '.join(missing)}.", file=sys.stderr)
        return 1

    commands = [
        ("Brain", [str(VENV_PYTHON), "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"], BACKEND),
        ("Console", [npm, "run", "dev"], CONSOLE),
        ("Agent", [dotnet, "run", "--project", str(AGENT_PROJECT)], ROOT),
    ]
    processes: dict[str, subprocess.Popen] = {}
    lock_created = False
    try:
        for name, command, cwd in commands:
            kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}
            processes[name] = subprocess.Popen(command, cwd=cwd, **kwargs)

        pids = {name: process.pid for name, process in processes.items()}
        with LOCK_FILE.open("x", encoding="utf-8") as lock:
            lock_created = True
            lock.write(json.dumps(pids, indent=2) + "\n")
        print("VectorOne is running:")
        for name, pid in pids.items():
            print(f"  {name}: PID {pid}")
        print("Press Ctrl+C to stop all components.")

        while True:
            for name, process in processes.items():
                exit_code = process.poll()
                if exit_code is not None:
                    print(f"{name} exited with code {exit_code}; stopping the remaining components.")
                    return 1 if exit_code else 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping VectorOne...")
        return 0
    except (OSError, ValueError) as error:
        print(f"Could not start VectorOne: {error}", file=sys.stderr)
        return 1
    finally:
        for name, process in processes.items():
            terminate_child(process, name)
        if lock_created and LOCK_FILE.exists():
            LOCK_FILE.unlink()


def stop() -> int:
    if not LOCK_FILE.exists():
        print("VectorOne is not running (no lock file found).")
        return 0

    try:
        pids = read_lock()
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    success = True
    for name, pid in pids.items():
        success = stop_pid(pid, name) and success

    if success:
        LOCK_FILE.unlink(missing_ok=True)
        print("VectorOne stopped.")
        return 0
    print(f"Some processes could not be stopped; {LOCK_FILE.name} was retained.", file=sys.stderr)
    return 1


def status() -> int:
    if not LOCK_FILE.exists():
        print("VectorOne is not running.")
        return 0

    try:
        pids = read_lock()
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    active = {name: pid for name, pid in pids.items() if process_is_running(pid)}
    if not active:
        print("VectorOne is not running (no active processes).")
        return 1

    print("VectorOne is running:")
    for name, pid in active.items():
        print(f"  {name}: PID {pid}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage the VectorOne platform.")
    parser.add_argument("command", choices=("start", "stop", "status"))
    args = parser.parse_args()
    return {"start": start, "stop": stop, "status": status}[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
