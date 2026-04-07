#!/usr/bin/env python3
"""
cli.py — Interactive CLI for the password-hashing education series

Commands
--------
  demo <step>       Run a single educational demo (1-8 or 'all')
  register          Create an account in the live login system
  login             Authenticate against the live login system
  passwd            Change your password
  whoami            Show your stored user record
  users             List all registered accounts
  stats             Show hash-scheme distribution
  import-legacy     Seed the live DB with legacy users to watch migration
  help              Show this screen

Steps map:
  1  hash            bcrypt vs MD5/SHA-256 basics
  2  rainbow         Rainbow table attack
  3  brute           Brute force & dictionary attack
  4  timing          Timing attack & constant-time comparison
  5  salt            Salt deep dive
  6  cost            Cost factor benchmarking
  7  pepper          Pepper / secret key hardening
  8  upgrade         Hash upgrade / migration strategy
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time
import textwrap
import getpass

# ── Colour helpers (degrade gracefully on Windows without colorama) ────────────

try:
    import colorama
    colorama.init()
    _COLOURS = True
except ImportError:
    _COLOURS = False

def _c(code: str, text: str) -> str:
    if not _COLOURS:
        return text
    codes = {
        "red":    "\033[91m",
        "green":  "\033[92m",
        "yellow": "\033[93m",
        "blue":   "\033[94m",
        "cyan":   "\033[96m",
        "bold":   "\033[1m",
        "reset":  "\033[0m",
    }
    return codes.get(code, "") + text + codes["reset"]


# ── Login system singleton ─────────────────────────────────────────────────────

from login_system import LoginSystem, Config, Scheme, CURRENT_SCHEME

_DB_PATH = "passwords_demo.db"
_PEPPER_ENV = "DEMO_APP_PEPPER"

def _get_pepper() -> bytes:
    raw = os.environ.get(_PEPPER_ENV)
    if raw:
        return bytes.fromhex(raw)
    pepper = os.urandom(32)
    os.environ[_PEPPER_ENV] = pepper.hex()
    return pepper

_system = LoginSystem(Config(
    bcrypt_rounds=12,
    pepper=_get_pepper(),
    db_path=_DB_PATH,
))


# ── Demo imports ───────────────────────────────────────────────────────────────

def _run_demo(step: str) -> None:
    step = step.strip().lower()

    demos = {
        "1": ("hash",    "hash.py",            None),
        "hash": ("hash", "hash.py",            None),
        "2": ("rainbow", "rainbow_table.py",   None),
        "rainbow": ("rainbow", "rainbow_table.py", None),
        "3": ("brute",   "brute_force.py",     None),
        "brute": ("brute", "brute_force.py",   None),
        "4": ("timing",  "timing_attack.py",   None),
        "timing": ("timing", "timing_attack.py", None),
        "5": ("salt",    "salt_deep.py",        None),
        "salt": ("salt", "salt_deep.py",        None),
        "6": ("cost",    "cost_factor.py",      None),
        "cost": ("cost", "cost_factor.py",      None),
        "7": ("pepper",  "pepper.py",           None),
        "pepper": ("pepper", "pepper.py",       None),
        "8": ("upgrade", "upgrade_strategy.py", None),
        "upgrade": ("upgrade", "upgrade_strategy.py", None),
    }

    if step == "all":
        for key in ["1","2","3","4","5","6","7","8"]:
            _run_demo(key)
            print()
        return

    if step not in demos:
        print(_c("red", f"Unknown step: '{step}'"))
        print("Valid steps: 1-8 or names: hash, rainbow, brute, timing, salt, cost, pepper, upgrade")
        return

    name, module_file, _ = demos[step]
    print(_c("bold", f"\n{'─'*60}"))
    print(_c("cyan",  f"  Running step: {name}  ({module_file})"))
    print(_c("bold", f"{'─'*60}\n"))

    # Each module runs its demo when called as __main__ — replicate that here
    # by importing and calling its demonstrate_* function directly.
    _dispatch = {
        "hash":    _demo_hash,
        "rainbow": _demo_rainbow,
        "brute":   _demo_brute,
        "timing":  _demo_timing,
        "salt":    _demo_salt,
        "cost":    _demo_cost,
        "pepper":  _demo_pepper,
        "upgrade": _demo_upgrade,
    }
    _dispatch[name]()


def _demo_hash():
    from hash import demonstrate_weaknesses, hash_password_bcrypt, verify_password_bcrypt
    pw = "MyPassword123"
    print("=== SECURE: bcrypt ===")
    t = time.perf_counter()
    h = hash_password_bcrypt(pw)
    ms = (time.perf_counter() - t) * 1000
    print(f"Hash: {h}")
    print(f"Time: {ms:.1f}ms")
    print(f"Verified: {verify_password_bcrypt(pw, h)}")
    print("\n=== WEAK: MD5 and SHA-256 ===")
    for algo, data in demonstrate_weaknesses(pw).items():
        print(f"\n{algo.upper()}")
        print(f"  Hash:                     {data['hash']}")
        print(f"  Time:                     {data['time_ms']}ms")
        print(f"  No salt:                  {data['no_salt']}")
        print(f"  Same input = same output: {data['same_input_same_output']}")

def _demo_rainbow():
    from rainbow_table import demonstrate_rainbow_table_attack
    demonstrate_rainbow_table_attack("monkey123")

def _demo_brute():
    from brute_force import demonstrate_brute_force_attack
    demonstrate_brute_force_attack()

def _demo_timing():
    from timing_attack import demonstrate_timing_attack
    demonstrate_timing_attack()

def _demo_salt():
    from salt_deep import demonstrate_salt_deep_dive
    demonstrate_salt_deep_dive()

def _demo_cost():
    from cost_factor import demonstrate_cost_factor
    demonstrate_cost_factor()

def _demo_pepper():
    from pepper import demonstrate_pepper
    demonstrate_pepper()

def _demo_upgrade():
    from upgrade_strategy import demonstrate_upgrade_strategy
    demonstrate_upgrade_strategy()


# ── Live system commands ───────────────────────────────────────────────────────

def _cmd_register() -> None:
    print(_c("bold", "\n── Register ──"))
    username = input("  Username: ").strip()
    if not username:
        print(_c("red", "  Username cannot be empty."))
        return
    password = getpass.getpass("  Password: ")
    confirm  = getpass.getpass("  Confirm:  ")
    if password != confirm:
        print(_c("red", "  Passwords do not match."))
        return
    try:
        _system.register(username, password)
        print(_c("green", f"  ✓ Account '{username}' created."))
    except ValueError as e:
        print(_c("red", f"  ✗ {e}"))


def _cmd_login() -> None:
    print(_c("bold", "\n── Login ──"))
    username = input("  Username: ").strip()
    password = getpass.getpass("  Password: ")

    result = _system.login(username, password)
    colour = "green" if result.success else "red"
    symbol = "✓" if result.success else "✗"
    print(_c(colour, f"  {symbol} {result.message}"))
    print(f"    Elapsed: {result.elapsed_ms:.0f}ms")
    if result.hash_upgraded:
        print(_c("yellow", f"    Hash upgraded: {result.old_scheme} → {result.new_scheme}"))


def _cmd_passwd() -> None:
    print(_c("bold", "\n── Change Password ──"))
    username     = input("  Username:     ").strip()
    old_password = getpass.getpass("  Old password: ")
    new_password = getpass.getpass("  New password: ")
    confirm      = getpass.getpass("  Confirm new:  ")

    if new_password != confirm:
        print(_c("red", "  Passwords do not match."))
        return

    ok = _system.change_password(username, old_password, new_password)
    if ok:
        print(_c("green", "  ✓ Password changed."))
    else:
        print(_c("red", "  ✗ Incorrect username or password."))


def _cmd_whoami() -> None:
    print(_c("bold", "\n── User Record ──"))
    username = input("  Username: ").strip()
    rec = _system.get_user(username)
    if rec is None:
        print(_c("red", f"  No user '{username}' found."))
        return

    print(f"  Username:        {rec.username}")
    print(f"  Scheme:          {rec.scheme}")
    print(f"  Hash:            {rec.password_hash[:40]}...")
    print(f"  Failed attempts: {rec.failed_attempts}")
    locked = rec.locked_until > time.time()
    print(f"  Locked:          {_c('red', 'YES') if locked else 'No'}")
    created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec.created_at))
    print(f"  Created at:      {created}")
    if rec.last_login_at:
        last = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec.last_login_at))
        print(f"  Last login:      {last}")


def _cmd_users() -> None:
    print(_c("bold", "\n── Registered Users ──"))
    users = _system.list_users()
    if not users:
        print("  (none)")
    for u in users:
        rec = _system.get_user(u)
        print(f"  {u:<20} scheme={rec.scheme}")


def _cmd_stats() -> None:
    print(_c("bold", "\n── Hash Scheme Distribution ──"))
    stats = _system.scheme_stats()
    if not stats:
        print("  (no users)")
        return

    gen_names = {s.value: g for s, g in {
        Scheme.MD5_PLAIN:     0,
        Scheme.SHA256_SALTED: 1,
        Scheme.BCRYPT_8:      2,
        Scheme.BCRYPT_12:     3,
        Scheme.BCRYPT_PEPPER: 4,
    }.items()}

    for scheme, count in sorted(stats.items(), key=lambda x: gen_names.get(x[0], 99)):
        gen = gen_names.get(scheme, "?")
        bar = "█" * count
        is_current = (scheme == CURRENT_SCHEME.value)
        label = _c("green", scheme + " ← current") if is_current else scheme
        print(f"  gen{gen}  {label:<45} {bar} ({count})")

    log = _system.upgrade_log()
    if log:
        print(_c("bold", "\n  Upgrade log:"))
        for e in log:
            t = time.strftime("%H:%M:%S", time.localtime(e["upgraded_at"]))
            print(f"    {t}  {e['username']:<12} {e['old_scheme']} → {e['new_scheme']}")


def _cmd_import_legacy() -> None:
    """Seed the live DB with representative legacy users for migration demo."""
    import hashlib, os

    legacy = [
        ("legacy_alice",  "Sunshine99",  Scheme.MD5_PLAIN.value,
         hashlib.md5("Sunshine99".encode()).hexdigest()),
        ("legacy_bob",    "Football12",  Scheme.SHA256_SALTED.value,
         _sha256_salted("Football12")),
    ]

    print(_c("bold", "\n── Import Legacy Users ──"))
    for username, pw, scheme, stored_hash in legacy:
        try:
            _system.import_legacy_user(username, scheme, stored_hash)
            print(_c("yellow", f"  ↑ Imported {username} ({scheme})"))
        except ValueError as e:
            print(_c("red", f"  ✗ {username}: {e}"))

    print()
    print("  Now run 'login' with these credentials to watch lazy migration:")
    print("    legacy_alice / Sunshine99")
    print("    legacy_bob   / Football12")


def _sha256_salted(password: str) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt + ":" + digest


def _cmd_help() -> None:
    print()
    print(_c("bold", "Password Hashing Education Series — CLI"))
    print()
    print(_c("cyan", "  Demo commands") + " (educational, no side effects):")
    steps = [
        ("demo 1 / demo hash",    "bcrypt vs MD5/SHA-256 basics"),
        ("demo 2 / demo rainbow", "Rainbow table attack"),
        ("demo 3 / demo brute",   "Brute force & dictionary attack"),
        ("demo 4 / demo timing",  "Timing attack & constant-time comparison"),
        ("demo 5 / demo salt",    "Salt deep dive"),
        ("demo 6 / demo cost",    "Cost factor benchmarking"),
        ("demo 7 / demo pepper",  "Pepper / secret key hardening"),
        ("demo 8 / demo upgrade", "Hash upgrade / migration strategy"),
        ("demo all",              "Run all 8 steps in sequence"),
    ]
    for cmd, desc in steps:
        print(f"    {_c('yellow', cmd):<30}  {desc}")

    print()
    print(_c("cyan", "  Live system commands") + " (interact with the real login system):")
    live = [
        ("register",       "Create a new account"),
        ("login",          "Authenticate"),
        ("passwd",         "Change password"),
        ("whoami",         "Inspect your stored user record"),
        ("users",          "List all accounts"),
        ("stats",          "Hash scheme distribution + upgrade log"),
        ("import-legacy",  "Seed DB with legacy users to demo migration"),
        ("help",           "Show this screen"),
        ("quit / exit",    "Exit"),
    ]
    for cmd, desc in live:
        print(f"    {_c('yellow', cmd):<30}  {desc}")
    print()


# ── REPL ──────────────────────────────────────────────────────────────────────

BANNER = """
╔══════════════════════════════════════════════════════════╗
║     Password Hashing Education Series — Interactive CLI  ║
║     8 steps from MD5 to bcrypt + pepper + migration      ║
╚══════════════════════════════════════════════════════════╝
  Type  'help'  to list commands.
  Type  'demo 1'  through  'demo 8'  (or  'demo all')  to run educational demos.
  Type  'register' / 'login'  to use the live login system.
"""

def _dispatch(line: str) -> bool:
    """Returns False to quit."""
    parts = line.strip().split(None, 1)
    if not parts:
        return True
    cmd  = parts[0].lower()
    rest = parts[1] if len(parts) > 1 else ""

    if cmd in ("quit", "exit", "q"):
        print("Goodbye.")
        return False
    elif cmd == "demo":
        if not rest:
            print(_c("red", "  Usage: demo <step>   e.g.  demo 1  or  demo all"))
        else:
            _run_demo(rest)
    elif cmd == "register":
        _cmd_register()
    elif cmd == "login":
        _cmd_login()
    elif cmd == "passwd":
        _cmd_passwd()
    elif cmd == "whoami":
        _cmd_whoami()
    elif cmd == "users":
        _cmd_users()
    elif cmd == "stats":
        _cmd_stats()
    elif cmd in ("import-legacy", "import_legacy"):
        _cmd_import_legacy()
    elif cmd == "help":
        _cmd_help()
    else:
        print(_c("red", f"  Unknown command: '{cmd}'  — type 'help' for a list"))

    return True


def main() -> None:
    print(BANNER)

    # If given a command on the command line, run it and exit
    if len(sys.argv) > 1:
        _dispatch(" ".join(sys.argv[1:]))
        return

    # REPL
    while True:
        try:
            line = input(_c("blue", "\n(cli) ") + "› ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not _dispatch(line):
            break


if __name__ == "__main__":
    main()