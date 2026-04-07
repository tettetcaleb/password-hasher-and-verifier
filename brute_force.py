import bcrypt
import hashlib
import time
import itertools
import string

# ── Steps 1 & 2 (unchanged) ──────────────────────────────────────────────────

def validate_password(password: str) -> bytes:
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if len(password) > 72:
        raise ValueError("Password exceeds bcrypt's 72-character limit.")
    return password.encode("utf-8")

def hash_password_bcrypt(password: str) -> bytes:
    password_bytes = validate_password(password)
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed

def verify_password_bcrypt(password: str, hashed: bytes) -> bool:
    password_bytes = validate_password(password)
    return bcrypt.checkpw(password_bytes, hashed)

def _hash_fast(algo: str, password: str) -> str:
    return hashlib.new(algo, password.encode("utf-8")).hexdigest()


# ── Step 3: Brute Force & Dictionary Attack ───────────────────────────────────

# When a password isn't in a rainbow table, attackers fall back to:
#   1. Dictionary attack  — try a wordlist of likely passwords
#   2. Brute force        — try every possible character combination
#
# The speed of MD5/SHA-256 makes both approaches practical.
# bcrypt's intentional slowness (cost factor) makes them infeasible at scale.

DICTIONARY = [
    # Common base words attackers try first
    "password", "password1", "password123",
    "qwerty123", "qwerty1234",
    "iloveyou1", "iloveyou12",
    "letmein12", "letmein123",
    "welcome12", "welcome123",
    "monkey123", "monkey1234",
    "dragon123", "dragon1234",
    "sunshine1", "sunshine12",
    "princess1", "princess12",
    "football1", "football12",
    "superman1", "superman12",
    "batman123", "batman1234",
    "shadow123", "shadow1234",
    "master123", "master1234",
    "hunter123", "hunter1234",
    "trustno11", "trustno112",
    "starwars1", "starwars12",
    "passw0rd1", "passw0rd12",
    "abc123456", "abc1234567",
    "12345678a", "123456789a",
]


def dictionary_attack_md5(target_hash: str) -> tuple[str | None, int, float]:
    """
    Tries each word in the dictionary against a target MD5 hash.
    Returns (cracked_password | None, attempts, elapsed_ms).
    """
    start = time.perf_counter()
    for i, word in enumerate(DICTIONARY, 1):
        if _hash_fast("md5", word) == target_hash:
            elapsed = (time.perf_counter() - start) * 1000
            return word, i, elapsed
    elapsed = (time.perf_counter() - start) * 1000
    return None, len(DICTIONARY), elapsed


def dictionary_attack_bcrypt(target_hash: bytes, wordlist: list[str]) -> tuple[str | None, int, float]:
    """
    Same dictionary attack against bcrypt.
    Each attempt is ~250ms — shows why the cost factor matters.
    Caps at 5 attempts to keep the demo from running forever.
    """
    cap = 5
    start = time.perf_counter()
    for i, word in enumerate(wordlist[:cap], 1):
        if bcrypt.checkpw(word.encode("utf-8"), target_hash):
            elapsed = (time.perf_counter() - start) * 1000
            return word, i, elapsed
    elapsed = (time.perf_counter() - start) * 1000
    return None, cap, elapsed


def brute_force_md5(
    target_hash: str,
    charset: str = string.ascii_lowercase + string.digits,
    max_length: int = 5,
    max_attempts: int = 500_000,
) -> tuple[str | None, int, float]:
    """
    Exhaustive brute force against an MD5 hash.
    Tries every combination up to max_length characters.
    Caps at max_attempts to keep the demo fast.
    """
    start = time.perf_counter()
    attempts = 0
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            if _hash_fast("md5", candidate) == target_hash:
                elapsed = (time.perf_counter() - start) * 1000
                return candidate, attempts, elapsed
            if attempts >= max_attempts:
                elapsed = (time.perf_counter() - start) * 1000
                return None, attempts, elapsed
    elapsed = (time.perf_counter() - start) * 1000
    return None, attempts, elapsed


def estimate_bcrypt_brute_force(charset_size: int, password_length: int, ms_per_hash: float = 250.0) -> dict:
    """
    Projects how long a brute force attack would take against bcrypt
    without actually running it (it would take centuries).
    """
    total_combinations = charset_size ** password_length
    seconds = (total_combinations * ms_per_hash) / 1000
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    years = days / 365.25
    return {
        "combinations": total_combinations,
        "ms_per_hash": ms_per_hash,
        "total_seconds": seconds,
        "years": years,
    }


def demonstrate_brute_force_attack() -> None:
    print("=" * 60)
    print("STEP 3: Brute Force & Dictionary Attack Demo")
    print("=" * 60)

    # ── Dictionary attack on MD5 ─────────────────────────────────
    target_password = "monkey123"
    target_md5 = _hash_fast("md5", target_password)

    print(f"\n[1] Dictionary attack on MD5 hash of '{target_password}'")
    print(f"    Target: {target_md5}")

    cracked, attempts, ms = dictionary_attack_md5(target_md5)
    if cracked:
        print(f"    CRACKED: '{cracked}' — {attempts} attempt(s) in {ms:.3f}ms")
    else:
        print(f"    Not found after {attempts} attempts ({ms:.1f}ms)")

    # ── Dictionary attack on SHA-256 ─────────────────────────────
    target_sha256 = _hash_fast("sha256", target_password)
    print(f"\n[2] Same dictionary attack on SHA-256")
    print(f"    Target: {target_sha256[:32]}...")

    start = time.perf_counter()
    cracked_sha = None
    sha_attempts = 0
    for word in DICTIONARY:
        sha_attempts += 1
        if _hash_fast("sha256", word) == target_sha256:
            cracked_sha = word
            break
    sha_ms = (time.perf_counter() - start) * 1000

    if cracked_sha:
        print(f"    CRACKED: '{cracked_sha}' — {sha_attempts} attempt(s) in {sha_ms:.3f}ms")
    else:
        print(f"    Not found after {sha_attempts} attempts ({sha_ms:.1f}ms)")

    # ── Brute force on a short MD5 hash ─────────────────────────
    short_target = "cat"   # short so brute force finds it quickly in the demo
    short_md5 = _hash_fast("md5", short_target)
    print(f"\n[3] Brute force MD5 — target is short word '{short_target}'")
    print(f"    Hash: {short_md5}")
    print(f"    Trying all lowercase+digit combos up to 5 chars (cap 500k)...")

    cracked_bf, bf_attempts, bf_ms = brute_force_md5(short_md5)
    if cracked_bf:
        print(f"    CRACKED: '{cracked_bf}' after {bf_attempts:,} attempts in {bf_ms:.1f}ms")
        rate = (bf_attempts / (bf_ms / 1000)) if bf_ms > 0 else 0
        print(f"    Throughput: ~{rate:,.0f} hashes/sec")
    else:
        print(f"    Not found in {bf_attempts:,} attempts ({bf_ms:.1f}ms)")

    # ── Dictionary attack on bcrypt (capped) ─────────────────────
    bcrypt_hash = hash_password_bcrypt(target_password)
    print(f"\n[4] Dictionary attack on bcrypt (capped at 5 attempts)")

    cracked_bc, bc_attempts, bc_ms = dictionary_attack_bcrypt(bcrypt_hash, DICTIONARY)
    if cracked_bc:
        print(f"    CRACKED: '{cracked_bc}' after {bc_attempts} attempt(s) in {bc_ms:.1f}ms")
    else:
        print(f"    Not cracked after {bc_attempts} attempt(s) — took {bc_ms:.1f}ms")
        per_attempt = bc_ms / bc_attempts if bc_attempts else 0
        print(f"    ~{per_attempt:.0f}ms per attempt (cost factor 12)")

    # ── Projection: brute force bcrypt ───────────────────────────
    print(f"\n[5] Projected brute force time against bcrypt")
    scenarios = [
        ("8-char lowercase only",    26, 8),
        ("8-char lowercase+digits",  36, 8),
        ("10-char mixed case+digits", 62, 10),
        ("12-char full printable",   95, 12),
    ]
    for label, charset_size, length in scenarios:
        est = estimate_bcrypt_brute_force(charset_size, length)
        combos = est["combinations"]
        years = est["years"]
        if years >= 1_000_000:
            time_str = f"{years:,.0f} years"
        elif years >= 1:
            time_str = f"{years:,.1f} years"
        else:
            time_str = f"{years * 365.25:.1f} days"
        print(f"    {label:<35} {combos:>20,.0f} combos → {time_str}")

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("  MD5/SHA-256 dictionary attack:  milliseconds")
    print("  MD5 brute force (short words):  milliseconds to seconds")
    print("  bcrypt dictionary (5 attempts): ~1-2 seconds for 5 guesses")
    print("  bcrypt brute force (8+ chars):  centuries to heat death of universe")
    print()
    print("  The cost factor (rounds=12) is the entire game.")
    print("  It doesn't make one hash slower — it makes billions of hashes impossible.")


if __name__ == "__main__":
    demonstrate_brute_force_attack()