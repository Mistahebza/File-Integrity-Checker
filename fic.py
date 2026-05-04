#!/usr/bin/env python3
"""
File Integrity Checker
Verifies log files for unauthorized tampering using SHA-256 hashing.
"""

import argparse
import hashlib
import json
import os
import sys
import stat
import time
from datetime import datetime
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────
STORE_DIR  = Path.home() / ".file_integrity"
STORE_FILE = STORE_DIR / "hashes.json"
LOG_FILE   = STORE_DIR / "audit.log"

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

LOG_EXTS = {".log", ".txt", ".json", ".csv", ".xml", ".out", ".err", ".trace"}


# ── Helpers ──────────────────────────────────────────────────────────────────
def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def err(msg: str) -> None:
    print(f"{RED}[ERROR]{RESET} {msg}", file=sys.stderr)

def ok(msg: str) -> None:
    print(f"{GREEN}[OK]{RESET}    {msg}")

def warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{RESET}  {msg}")

def info(msg: str) -> None:
    print(f"{CYAN}[INFO]{RESET}  {msg}")


def _ensure_store() -> None:
    """Create the secure store directory with restricted permissions."""
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    # Owner read/write/execute only (700)
    os.chmod(STORE_DIR, stat.S_IRWXU)


def _load_store() -> dict:
    if not STORE_FILE.exists():
        return {}
    try:
        with open(STORE_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        err(f"Could not read hash store: {e}")
        sys.exit(1)


def _save_store(data: dict) -> None:
    _ensure_store()
    tmp = STORE_FILE.with_suffix(".tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        # Owner read/write only (600)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(STORE_FILE)
    except OSError as e:
        err(f"Could not write hash store: {e}")
        tmp.unlink(missing_ok=True)
        sys.exit(1)


def _audit(message: str) -> None:
    """Append a timestamped entry to the audit log."""
    _ensure_store()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{now()}] {message}\n")
        os.chmod(LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Audit log failure is non-fatal


# ── Core ─────────────────────────────────────────────────────────────────────
def sha256_file(path: Path, chunk: int = 65536) -> str:
    """Return the lowercase hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def collect_files(target: str) -> list[Path]:
    """Return a sorted list of files to check from a path (file or directory)."""
    p = Path(target).resolve()
    if not p.exists():
        err(f"Path does not exist: {p}")
        sys.exit(1)
    if p.is_file():
        return [p]
    if p.is_dir():
        files = sorted(
            f for f in p.rglob("*")
            if f.is_file() and f.suffix.lower() in LOG_EXTS
        )
        if not files:
            warn(f"No recognised log files found under {p}")
            warn(f"Recognised extensions: {', '.join(sorted(LOG_EXTS))}")
            sys.exit(0)
        return files
    err(f"Not a file or directory: {p}")
    sys.exit(1)


def _fmt_size(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_check(target: str, verbose: bool) -> None:
    """Compute hashes and compare against stored baseline."""
    files  = collect_files(target)
    store  = _load_store()
    is_new = not store

    print(f"\n{BOLD}File Integrity Check{RESET}  —  {now()}")
    print(f"{DIM}Target : {Path(target).resolve()}{RESET}")
    print(f"{DIM}Store  : {STORE_FILE}{RESET}")
    print()

    if is_new:
        info("No baseline found — storing hashes now (first run).")
        print()

    results = {"ok": [], "tampered": [], "new": [], "missing": []}
    new_store = dict(store)

    # Check files present on disk
    for path in files:
        key = str(path)
        try:
            digest = sha256_file(path)
            mtime  = os.path.getmtime(path)
            size   = os.path.getsize(path)
        except OSError as e:
            warn(f"Cannot read {path}: {e}")
            continue

        if key not in store:
            results["new"].append(path)
            new_store[key] = {"hash": digest, "mtime": mtime, "size": size, "first_seen": now()}
            if verbose:
                info(f"NEW      {path.name}  ({_fmt_size(size)})")
        elif store[key]["hash"] != digest:
            results["tampered"].append(path)
            if verbose:
                print(f"{RED}[TAMPER]{RESET} {path.name}")
                print(f"         expected : {DIM}{store[key]['hash']}{RESET}")
                print(f"         got      : {DIM}{digest}{RESET}")
                old_mtime = datetime.fromtimestamp(store[key]["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
                new_mtime = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                print(f"         modified : {old_mtime}  →  {new_mtime}")
        else:
            results["ok"].append(path)
            if verbose:
                ok(f"OK       {path.name}  ({_fmt_size(size)})")

    # Detect files in baseline that are now missing
    checked_keys = {str(p) for p in files}
    for key in store:
        if key not in checked_keys and key.startswith(str(Path(target).resolve())):
            results["missing"].append(Path(key))
            if verbose:
                warn(f"MISSING  {Path(key).name}  (was in baseline)")

    # Update store and save
    _save_store(new_store)

    # Summary
    total    = len(files)
    n_ok     = len(results["ok"])
    n_bad    = len(results["tampered"])
    n_new    = len(results["new"])
    n_miss   = len(results["missing"])

    print()
    print(f"{BOLD}{'─'*50}{RESET}")
    print(f"  Total checked : {total}")
    print(f"  {GREEN}✓ Verified    : {n_ok}{RESET}")
    if n_bad:
        print(f"  {RED}✗ Tampered    : {n_bad}{RESET}")
    else:
        print(f"  ✗ Tampered    : {n_bad}")
    print(f"  ⊕ New files   : {n_new}")
    if n_miss:
        print(f"  {YELLOW}⊘ Missing     : {n_miss}{RESET}")
    print(f"{BOLD}{'─'*50}{RESET}")

    if n_bad:
        print(f"\n{RED}{BOLD}⚠  INTEGRITY VIOLATION DETECTED — {n_bad} file(s) may have been tampered with.{RESET}\n")
        for p in results["tampered"]:
            print(f"   {RED}→  {p}{RESET}")
        print()
    elif not verbose and n_new == 0 and n_miss == 0:
        print(f"\n{GREEN}{BOLD}✓  All {n_ok} file(s) passed integrity check.{RESET}\n")
    else:
        print()

    # Audit
    _audit(
        f"CHECK target={target} total={total} ok={n_ok} "
        f"tampered={n_bad} new={n_new} missing={n_miss}"
    )

    sys.exit(1 if n_bad else 0)


def cmd_init(target: str) -> None:
    """Re-initialise: re-hash all files and overwrite the stored baseline."""
    files = collect_files(target)
    store = _load_store()

    existing = sum(1 for p in files if str(p) in store)
    print(f"\n{BOLD}Re-initialise Baseline{RESET}  —  {now()}")
    print(f"{DIM}Target : {Path(target).resolve()}{RESET}")
    if existing:
        print(f"{YELLOW}This will overwrite {existing} existing baseline entr{'y' if existing==1 else 'ies'}.{RESET}")
        answer = input("Continue? [y/N] ").strip().lower()
        if answer != "y":
            info("Aborted.")
            return

    new_store = dict(store)
    count = 0
    for path in files:
        try:
            digest = sha256_file(path)
            new_store[str(path)] = {
                "hash"      : digest,
                "mtime"     : os.path.getmtime(path),
                "size"      : os.path.getsize(path),
                "first_seen": now(),
            }
            count += 1
            ok(f"Stored  {path.name}")
        except OSError as e:
            warn(f"Skipped {path}: {e}")

    _save_store(new_store)
    _audit(f"INIT target={target} files_stored={count}")
    print(f"\n{GREEN}{BOLD}✓  Baseline stored for {count} file(s).{RESET}\n")


def cmd_list() -> None:
    """Print all entries currently in the hash store."""
    store = _load_store()
    if not store:
        info("The hash store is empty.")
        return

    print(f"\n{BOLD}Stored Baseline Entries{RESET}  ({len(store)} file(s))\n")
    for key, meta in sorted(store.items()):
        first = meta.get("first_seen", "—")
        size  = _fmt_size(meta.get("size", 0))
        print(f"  {CYAN}{Path(key).name}{RESET}")
        print(f"    path       : {DIM}{key}{RESET}")
        print(f"    sha256     : {DIM}{meta['hash']}{RESET}")
        print(f"    size       : {size}")
        print(f"    first seen : {first}")
        print()


def cmd_purge(target: str | None) -> None:
    """Remove entries from the store (all, or only those under a target path)."""
    store = _load_store()
    if not store:
        info("Hash store is already empty.")
        return

    if target:
        prefix = str(Path(target).resolve())
        keys   = [k for k in store if k.startswith(prefix)]
    else:
        keys = list(store.keys())

    if not keys:
        info("No matching entries found.")
        return

    print(f"{YELLOW}About to remove {len(keys)} entr{'y' if len(keys)==1 else 'ies'} from the store.{RESET}")
    answer = input("Continue? [y/N] ").strip().lower()
    if answer != "y":
        info("Aborted.")
        return

    for k in keys:
        del store[k]
    _save_store(store)
    _audit(f"PURGE target={target or 'ALL'} removed={len(keys)}")
    ok(f"Removed {len(keys)} entr{'y' if len(keys)==1 else 'ies'}.")


def cmd_log(lines: int) -> None:
    """Print the audit log tail."""
    if not LOG_FILE.exists():
        info("No audit log found.")
        return
    with open(LOG_FILE, "r") as f:
        entries = f.readlines()
    tail = entries[-lines:]
    print(f"\n{BOLD}Audit Log{RESET}  (last {len(tail)} entries)\n")
    for line in tail:
        print(f"  {DIM}{line.rstrip()}{RESET}")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fic",
        description="File Integrity Checker — detect tampering in log files via SHA-256.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  fic check /var/log/app          # verify all log files in a directory
  fic check /var/log/app/app.log  # verify a single file
  fic check /var/log/app -v       # verbose output per file
  fic init  /var/log/app          # (re-)initialise baseline
  fic list                        # show all stored hashes
  fic purge /var/log/app          # remove entries for a path
  fic purge                       # remove ALL entries
  fic log                         # show last 20 audit entries
  fic log -n 50                   # show last 50 audit entries
        """,
    )
    sub = p.add_subparsers(dest="cmd", metavar="command")

    # check
    pc = sub.add_parser("check", help="verify file hashes against stored baseline")
    pc.add_argument("target", help="file or directory to check")
    pc.add_argument("-v", "--verbose", action="store_true", help="show result for every file")

    # init
    pi = sub.add_parser("init", help="(re-)initialise baseline hashes")
    pi.add_argument("target", help="file or directory to hash")

    # list
    sub.add_parser("list", help="list all stored baseline entries")

    # purge
    pp = sub.add_parser("purge", help="remove entries from the store")
    pp.add_argument("target", nargs="?", default=None, help="limit to this path (omit for all)")

    # log
    pl = sub.add_parser("log", help="show the audit log")
    pl.add_argument("-n", "--lines", type=int, default=20, metavar="N", help="number of lines (default 20)")

    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        sys.exit(0)

    if args.cmd == "check":
        cmd_check(args.target, args.verbose)
    elif args.cmd == "init":
        cmd_init(args.target)
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "purge":
        cmd_purge(args.target)
    elif args.cmd == "log":
        cmd_log(args.lines)


if __name__ == "__main__":
    main()