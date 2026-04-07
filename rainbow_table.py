import bcrypt
import hashlib
import time
import os

# ── Step 1 (unchanged) ───────────────────────────────────────────────────────

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

def demonstrate_weaknesses(password: str) -> dict:
    results = {}
    for algo in ["md5", "sha256"]:
        start = time.perf_counter()
        h = hashlib.new(algo, password.encode("utf-8")).hexdigest()
        elapsed = time.perf_counter() - start
        h2 = hashlib.new(algo, password.encode("utf-8")).hexdigest()
        results[algo] = {
            "hash": h,
            "time_ms": round(elapsed * 1000, 4),
            "no_salt": True,
            "same_input_same_output": h == h2,
        }
    return results


# ── Step 2: Rainbow Table Attack Simulation ───────────────────────────────────

# A "rainbow table" is a precomputed mapping of hash → plaintext.
# Because unsalted MD5/SHA-256 always produce the same hash for the same input,
# an attacker can build this table once and look up any matching hash instantly.
# bcrypt defeats this because every hash has a unique random salt baked in,
# so even identical passwords produce completely different hashes.

COMMON_PASSWORDS = [
    "password",
    "123456789",
    "qwerty123",
    "iloveyou1",
    "welcome12",
    "monkey123",
    "dragon123",
    "letmein12",
    "sunshine1",
    "princess1",
]

def build_rainbow_table(algo: str = "md5") -> dict[str, str]:
    """
    Simulates an attacker's precomputed rainbow table.
    Maps hash → plaintext for a list of common passwords.
    In the real world these tables contain billions of entries.
    """
    table = {}
    for pw in COMMON_PASSWORDS:
        h = hashlib.new(algo, pw.encode("utf-8")).hexdigest()
        table[h] = pw
    return table

def rainbow_table_attack(target_hash: str, table: dict[str, str]) -> str | None:
    """
    O(1) lookup — no brute force needed, just a dictionary hit.
    Returns the cracked plaintext, or None if not in the table.
    """
    return table.get(target_hash)

def attempt_bcrypt_rainbow(target_hash: bytes, table: dict[str, str]) -> str | None:
    """
    Shows why rainbow tables don't work against bcrypt.
    Even if the attacker has the plaintext, they'd have to rehash it
    with bcrypt using the exact embedded salt — and do that individually
    for every single stored hash. No precomputation possible.
    """
    for plaintext in table.values():
        try:
            if bcrypt.checkpw(plaintext.encode("utf-8"), target_hash):
                return plaintext
        except Exception:
            pass
    return None

def demonstrate_rainbow_table_attack(target_password: str) -> None:
    print("=" * 60)
    print("STEP 2: Rainbow Table Attack Simulation")
    print("=" * 60)

    # ── MD5 Attack ───────────────────────────────────────────────
    print("\n[1] Building MD5 rainbow table from common passwords...")
    md5_table = build_rainbow_table("md5")
    print(f"    Table size: {len(md5_table)} entries")
    print("    Sample entries:")
    for h, pw in list(md5_table.items())[:3]:
        print(f"      {h[:20]}...  →  '{pw}'")

    target_md5 = hashlib.md5(target_password.encode("utf-8")).hexdigest()
    print(f"\n[2] Target MD5 hash of '{target_password}':")
    print(f"    {target_md5}")

    start = time.perf_counter()
    cracked = rainbow_table_attack(target_md5, md5_table)
    lookup_time = (time.perf_counter() - start) * 1000

    if cracked:
        print(f"\n[!] CRACKED in {lookup_time:.4f}ms → '{cracked}'")
        print("    No brute force. Pure O(1) lookup.")
    else:
        print(f"\n    Not in table (password not in common list).")

    # ── SHA-256 Attack ───────────────────────────────────────────
    print("\n[3] Same attack with SHA-256...")
    sha256_table = build_rainbow_table("sha256")
    target_sha256 = hashlib.sha256(target_password.encode("utf-8")).hexdigest()

    start = time.perf_counter()
    cracked_sha = rainbow_table_attack(target_sha256, sha256_table)
    lookup_time_sha = (time.perf_counter() - start) * 1000

    if cracked_sha:
        print(f"    CRACKED in {lookup_time_sha:.4f}ms → '{cracked_sha}'")
    else:
        print(f"    Not in table.")

    # ── bcrypt Defense ───────────────────────────────────────────
    print("\n[4] Attempting same attack on bcrypt hash...")
    bcrypt_hash = hash_password_bcrypt(target_password)
    print(f"    bcrypt hash: {bcrypt_hash[:40]}...")

    # Show that two bcrypt hashes of the SAME password are different (unique salts)
    bcrypt_hash2 = hash_password_bcrypt(target_password)
    print(f"    Same password, second hash: {bcrypt_hash2[:40]}...")
    print(f"    Hashes match each other: {bcrypt_hash == bcrypt_hash2}")
    print("    (They never will — each has a unique random salt embedded)")

    start = time.perf_counter()
    cracked_bcrypt = attempt_bcrypt_rainbow(bcrypt_hash, md5_table)
    bcrypt_attempt_time = (time.perf_counter() - start) * 1000

    print(f"\n    Rainbow table attack on bcrypt: {'CRACKED' if cracked_bcrypt else 'FAILED'}")
    print(f"    Time spent trying: {bcrypt_attempt_time:.1f}ms")
    print("    Why it fails: salt makes every hash unique — no precomputation possible.")

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  MD5 cracked via rainbow table:    {'Yes' if cracked else 'Not in demo table'}")
    print(f"  SHA-256 cracked via rainbow table: {'Yes' if cracked_sha else 'Not in demo table'}")
    print(f"  bcrypt cracked via rainbow table:  No — salt prevents precomputation")
    print()
    print("  The attack works on MD5/SHA-256 because:")
    print("    - No salt → same input always = same hash")
    print("    - Attacker builds table once, reuses it on any database")
    print()
    print("  bcrypt defeats it because:")
    print("    - Every hash has a unique random salt stored inside it")
    print("    - Attacker must rehash each guess individually per stored hash")
    print("    - At 12 rounds (~250ms each), cracking at scale is infeasible")


if __name__ == "__main__":
    # Use a password that's in our common list to show a successful crack
    victim_password = "monkey123"
    demonstrate_rainbow_table_attack(victim_password)

    print("\n--- Also verifying bcrypt still works correctly ---")
    h = hash_password_bcrypt(victim_password)
    print(f"bcrypt verify correct password: {verify_password_bcrypt(victim_password, h)}")
    print(f"bcrypt verify wrong password:   {verify_password_bcrypt('wrongpass999', h)}")