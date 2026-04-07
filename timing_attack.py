import bcrypt
import hashlib
import hmac
import time
import statistics

# ── Steps 1-3 (unchanged) ────────────────────────────────────────────────────

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


# ── Step 4: Timing Attack Demo ────────────────────────────────────────────────

# A timing attack exploits the fact that naive string comparison (==) stops
# as soon as it finds the first mismatched character. This means:
#   - A guess that matches 0 characters returns faster than one matching 5
#   - An attacker can measure response times to figure out the hash
#     one character at a time, turning an O(n^charset) problem into O(n*charset)
#
# The fix: constant-time comparison. Compare every byte regardless of where
# the mismatch occurs, so response time leaks nothing.
#
# bcrypt.checkpw uses constant-time comparison internally.
# hmac.compare_digest is the stdlib tool for this.

RUNS = 200  # number of timing samples per candidate


def naive_compare(a: str, b: str) -> bool:
    """
    Normal string equality. Exits at first mismatch.
    Leaks timing information proportional to how many characters match.
    """
    return a == b


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compares every byte regardless of where mismatch occurs.
    Response time is identical whether 0 or 31 characters match.
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def measure_comparison_time(
    target_hash: str,
    candidate_hash: str,
    compare_fn,
    runs: int = RUNS,
) -> float:
    """
    Runs the comparison many times and returns the median time in microseconds.
    Median is more stable than mean for timing — filters out OS scheduling noise.
    """
    times = []
    for _ in range(runs):
        start = time.perf_counter_ns()
        compare_fn(target_hash, candidate_hash)
        times.append(time.perf_counter_ns() - start)
    return statistics.median(times) / 1000  # nanoseconds → microseconds


def build_timing_candidates(target_hash: str) -> list[tuple[str, str]]:
    """
    Generates candidates with increasing prefix overlap against the target hash.
    Simulates an attacker probing character by character.
    Each candidate matches the target for the first N characters, then diverges.
    """
    candidates = []
    labels = []

    # No match at all
    all_zeros = "0" * len(target_hash)
    candidates.append(all_zeros)
    labels.append("0 chars match")

    # Increasing prefix matches
    for match_len in [4, 8, 16, 24, 31]:
        if match_len < len(target_hash):
            candidate = target_hash[:match_len] + "0" * (len(target_hash) - match_len)
            candidates.append(candidate)
            labels.append(f"{match_len} chars match")

    # Full match
    candidates.append(target_hash)
    labels.append("full match")

    return list(zip(labels, candidates))


def demonstrate_timing_attack() -> None:
    print("=" * 60)
    print("STEP 4: Timing Attack Demo")
    print("=" * 60)

    target_password = "MyPassword123"
    target_md5 = _hash_fast("md5", target_password)

    print(f"\nTarget MD5 hash: {target_md5}")
    print(f"Each timing result is the median of {RUNS} runs.\n")

    candidates = build_timing_candidates(target_md5)

    # ── Naive comparison timing ───────────────────────────────────
    print("[1] Naive comparison (==) — timing leaks match length")
    print(f"    {'Candidate':<22} {'Naive (µs)':>12}")
    print("    " + "-" * 36)

    naive_times = []
    for label, candidate in candidates:
        t = measure_comparison_time(target_md5, candidate, naive_compare)
        naive_times.append(t)
        print(f"    {label:<22} {t:>12.3f}")

    # ── Constant-time comparison ──────────────────────────────────
    print(f"\n[2] Constant-time comparison (hmac.compare_digest) — timing is flat")
    print(f"    {'Candidate':<22} {'Const-time (µs)':>15}")
    print("    " + "-" * 39)

    ct_times = []
    for label, candidate in candidates:
        t = measure_comparison_time(target_md5, candidate, constant_time_compare)
        ct_times.append(t)
        print(f"    {label:<22} {t:>15.3f}")

    # ── Delta analysis ────────────────────────────────────────────
    print(f"\n[3] Timing delta: naive vs constant-time")
    naive_range = max(naive_times) - min(naive_times)
    ct_range = max(ct_times) - min(ct_times)
    print(f"    Naive range (max - min):         {naive_range:.3f} µs  ← attacker reads this")
    print(f"    Constant-time range (max - min): {ct_range:.3f} µs  ← nothing to read")

    # ── bcrypt checkpw ────────────────────────────────────────────
    print(f"\n[4] bcrypt.checkpw uses constant-time comparison internally")
    bcrypt_hash = hash_password_bcrypt(target_password)

    wrong_times = []
    correct_times = []

    # Time a few wrong guesses
    for _ in range(3):
        start = time.perf_counter_ns()
        verify_password_bcrypt("wrongpass1", bcrypt_hash)
        wrong_times.append((time.perf_counter_ns() - start) / 1e6)

    # Time correct password
    for _ in range(3):
        start = time.perf_counter_ns()
        verify_password_bcrypt(target_password, bcrypt_hash)
        correct_times.append((time.perf_counter_ns() - start) / 1e6)

    print(f"    Wrong password  — median: {statistics.median(wrong_times):.1f}ms")
    print(f"    Correct password — median: {statistics.median(correct_times):.1f}ms")
    print(f"    Timing difference is noise, not signal — bcrypt dominates the cost")

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("  Naive == comparison:       leaks match length via timing")
    print("  hmac.compare_digest:       flat timing — leaks nothing")
    print("  bcrypt.checkpw:            constant-time + slow — double protection")
    print()
    print("  Rule: never compare hashes with ==")
    print("  Always use hmac.compare_digest or a library that does it for you.")


if __name__ == "__main__":
    demonstrate_timing_attack()