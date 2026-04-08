Password Hasher & Verifier
So this project started as me trying to actually understand password security, not just use bcrypt because some tutorial told me to. I wanted to know why MD5 is bad, like actually demonstrate it, not just take it on faith. Ended up turning into a full 8-step series that builds from the ground up each step adds one new attack or concept, and by the end there's a working auth system that handles legacy hash migration, account lockout, timing safety, all of it.
What's in here
Steps 1–8 are educational demos. Each one focuses on one attack or concept:
StepFileWhat it covers1hash.pybcrypt vs MD5/SHA-256  why slow hashing matters2rainbow_table.pyRainbow table attacks  O(1) hash cracking in action3brute_force.pyDictionary + brute force throughput is the real threat4timing_attack.pyWhy == leaks info and how constant-time comparison fixes it5salt_deep.pySalt deep dive per-user vs global vs none6cost_factor.pyBenchmarking bcrypt rounds 4–14 on real hardware7pepper.pyHMAC pepper as a second layer of defense8upgrade_strategy.pyLazy migration upgrading old hashes without forcing resets
login_system.py is the production backend that ties all of it together — bcrypt + pepper, account lockout, transparent hash upgrades, SQLite storage, audit log.
cli.py is an interactive REPL that lets you run any of the demos or interact with the live auth system in real time.
Why I built it this way
I didn't just want to show "bcrypt good, MD5 bad." I wanted to show the mechanism an actual rainbow table lookup, actual brute force timing numbers, an actual timing leak you can measure in microseconds. Each step is designed so you can see the attack first, then see why the defense works.
The login system at the end is where it all comes together. It supports 5 hash generations (MD5 up through bcrypt + pepper) and will automatically re-hash any legacy account on login. So you can import an old MD5 user, log in as them, and watch the upgrade happen live.
Quick start
bashpip install bcrypt colorama
python cli.py
Recommended walkthrough (takes about 20 min):
demo 1        # why bcrypt exists
demo 2        # why unsalted hashes are catastrophic  
demo 3        # brute force economics
demo 4        # timing attacks
demo 5        # how salt actually works
demo 6        # benchmark cost factor on your machine
demo 7        # pepper
demo 8        # legacy hash migration

import-legacy # seed two old accounts (MD5 + SHA-256)
login         # log in as one, watch thehash upgrade
stats         # confirm they're now gen 4
Or run a single demo and exit:
bashpython cli.py demo 3
python cli.py demo all
The login system
pythonfrom login_system import LoginSystem, Config
import os

system = LoginSystem(Config(
    bcrypt_rounds=12,
    pepper=bytes.fromhex(os.environ["APP_PEPPER"]),
    db_path="users.db",
))

system.register("alice", "HunterTwo99!")
result = system.login("alice", "HunterTwo99!")
print(result.success, result.hash_upgraded, f"{result.elapsed_ms:.0f}ms")
Hash generations supported:
GenSchemeNotes0MD5 (plain)Import only — never register1SHA-256 (salted)Import only2bcrypt cost=8Import only3bcrypt cost=12Acceptable baseline4bcrypt + HMAC pepperCurrent target
All gen 0–3 accounts upgrade transparently on next login. No forced resets, no user friction.
Config
python@dataclass
class Config:
    bcrypt_rounds:       int   = 12         # OWASP min=10, recommended=12
    pepper:              bytes = os.urandom(32)
    db_path:             str   = ":memory:"
    max_login_attempts:  int   = 5
    lockout_seconds:     int   = 300        # 5 min
    min_password_len:    int   = 8
    max_password_len:    int   = 72         # bcrypt hard limit
Pepper should come from an environment variable or secrets manager, not hardcoded. The CLI generates a fresh one per session — if you want it to persist across restarts, save it manually:
bashpython3 -c "import os; print(os.urandom(32).hex())" > .pepper
export DEMO_APP_PEPPER=$(cat .pepper)
Things I learned building this
The cost factor stuff was probably the most eye-opening. On my machine MD5 runs at around 3.8 million hashes/second. bcrypt at rounds=12 runs at about 1.3 hashes/second. That's not a rounding error — that's the entire point. An attacker with a GPU can push MD5 into the billions per second range, but bcrypt's cost factor is hardware-agnostic. You're paying ~250ms per attempt no matter what you throw at it.
The timing attack step was also suprising to me — the difference between == and hmac.compare_digest is literally a few hundred nanoseconds per character matched, but that's measurable, and in a real system with enough samples it leaks hash prefix information. One line fix but easy to miss.
Dependencies
bcrypt
colorama   # optional, for color output
hashlib    # stdlib
hmac       # stdlib
itertools  # stdlib
statistics # stdlib
sqlite3    # stdlib
