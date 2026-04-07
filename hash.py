import bcrypt
import hashlib
import time
import os

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

if __name__ == "__main__":
    test_password = "MyPassword123"

    print("=== SECURE: bcrypt ===")
    start = time.perf_counter()
    hashed = hash_password_bcrypt(test_password)
    bcrypt_time = time.perf_counter() - start
    print(f"Hash: {hashed}")
    print(f"Time: {round(bcrypt_time * 1000, 1)}ms")
    print(f"Verified: {verify_password_bcrypt(test_password, hashed)}")

    print("\n=== WEAK: MD5 and SHA-256 ===")
    weaknesses = demonstrate_weaknesses(test_password)
    for algo, data in weaknesses.items():
        print(f"\n{algo.upper()}")
        print(f"  Hash:              {data['hash']}")
        print(f"  Time:              {data['time_ms']}ms")
        print(f"  No salt:           {data['no_salt']}")
        print(f"  Same input = same output: {data['same_input_same_output']}")