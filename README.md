# password-hasher-and-verifier
This project hashes a password, verifies it and shows MD5 vs SHA-256 weaknes


 Password Hasher & Verifier Step 1 Core Hashing Foundation
 What I’m doing here
In this step I set up the foundation for handling passwords correctly. I wanted to make sure I wasn’t just hashing passwords but actually doing it in a secure way and understanding why it matters.
So I focused on three things
Input validation to make sure passwords meet basic rules
 Secure hashing using bcrypt which is designed for passwords
 A comparison with MD5 and SHA 256 to show why fast hashing is dangerous

 File
Password_hasher.py
 Functions
validate_password(password: str) -> bytes
This is where I handle all input validation before anything else happens
I make sure the input is actually a string
 I enforce a minimum length of 8 characters
 I enforce bcrypt’s 72 character limit
If everything is valid I convert the password into UTF 8 bytes since bcrypt requires bytes

hash_password_bcrypt(password: str) -> bytes
This is my main secure hashing function
I validate the password first
 I generate a random salt using bcrypt
 I hash the password with a cost factor of 12
The result already includes the salt so I don’t need to store it separately

verify_password_bcrypt(password: str, hashed: bytes) -> bool
This is used when checking a login attempt
I validate and encode the input password
 I use bcrypt’s check function to compare it with the stored hash
It returns true if the password matches and false if it doesn’t

demonstrate_weaknesses(password: str) -> dict
I added this to clearly show why MD5 and SHA 256 should not be used for passwords
For both algorithms I measure how fast they run
 I hash the same password twice
 I store the results so they can be compared
This highlights two big problems
 There is no salt
 The same input always gives the same output

 Sample Output
=== SECURE bcrypt ===
Hash b'$2b$12$...'
Time ~250ms
Verified True

=== WEAK MD5 and SHA 256 ===

MD5
 Hash <32 char hex>
 Time 0.003ms
 No salt True
 Same input = same output True

SHA256
 Hash <64 char hex>
 Time 0.002ms
 No salt True
 Same input = same output True
What I learned
bcrypt is built for passwords while MD5 and SHA 256 are not
bcrypt is slow on purpose which makes brute force attacks harder
 MD5 and SHA 256 are extremely fast which makes them easy to attack
bcrypt automatically uses a unique salt every time
 MD5 and SHA 256 do not use salt by default
The same password will not produce the same bcrypt hash twice
 The same password will always produce the same MD5 or SHA 256 hash
 Dependencies
bcrypt
hashlib
Install bcrypt with
python -m pip install bcrypt

Password Hasher & Verifier Step 2: Rainbow Table Attack Simulation
What This Step Does
Demonstrates why unsalted hashes are dangerous by simulating a real rainbow table attack. The point isn't just to say "MD5 is bad" —it's to show the exact mechanism an attacker uses to crack unsalted hashes instantly, and then show why bcrypt makes that completely infeasible.

File
password_hasher_step2.py

New Functions
build_rainbow_table(algo: str) -> dict[str, str]
Simulates an attacker's precomputed lookup table. Maps hash → plaintext for a list of common passwords. In real attacks these tables contain billions of entries and are freely available to download.
rainbow_table_attack(target_hash: str, table: dict) -> str | None
O(1) dictionary lookup — no brute force, no iteration. If the hash is in the table, it cracks instantly. Shows that once the table is built, the "attack" is just a key lookup.
attempt_bcrypt_rainbow(target_hash: bytes, table: dict) -> str | None
Tries the same rainbow table strategy against a bcrypt hash. Fails — because bcrypt's embedded salt means no precomputation is possible. Each guess must be verified individually using bcrypt.checkpw.
demonstrate_rainbow_table_attack(target_password: str)
Runs the full end-to-end demo: builds the table, cracks MD5, cracks SHA-256, fails against bcrypt, and explains why at each step.

Sample Output
============================================================
STEP 2: Rainbow Table Attack Simulation
============================================================

[1] Building MD5 rainbow table from common passwords...
    Table size: 10 entries
    Sample entries:
      ab87d24bdc7452e5...  →  'password'
      ...

[2] Target MD5 hash of 'monkey123':
    7a4c7d0e2c3f1b8a...

[!] CRACKED in 0.0012ms → 'monkey123'
    No brute force. Pure O(1) lookup.

[3] Same attack with SHA-256...
    CRACKED in 0.0009ms → 'monkey123'

[4] Attempting same attack on bcrypt hash...
    bcrypt hash: b'$2b$12$...'
    Same password, second hash: b'$2b$12$...'  (different!)
    Hashes match each other: False

    Rainbow table attack on bcrypt: FAILED
    Time spent trying: ~250ms
    Why it fails: salt makes every hash unique — no precomputation possible.

The Core Insight


MD5 / SHA-256
bcrypt
Salt
None
Unique random salt per hash
Same password → same hash
Always
Never
Rainbow table viable
Yes
No
Crack time (if in table)
< 1ms
Infeasible

Unsalted hashes have a structural flaw: identical inputs always produce identical outputs. An attacker only needs to build the lookup table once and can reuse it against any database that uses the same algorithm. SHA-256 being "stronger" than MD5 doesn't help here — the vulnerability is the missing salt, not the algorithm's bit strength.
bcrypt kills this attack by embedding a unique random salt in every hash. There's no shared structure to precompute against. Each candidate password must be verified individually, and at 12 rounds (~250ms per check), attacking at scale is computationally infeasible.

Dependencies
Same as Step 1 — no new installs needed.
bcrypt
hashlib  # stdlib

Password Hasher & Verifier  Step 3: Brute Force & Dictionary Attack Demo
What This Step Does
Rainbow tables fail when the password isn't in the precomputed list. This step covers the fallback: dictionary attacks and brute force. Shows how fast MD5/SHA-256 makes both approaches practical, and how bcrypt's cost factor makes them infeasible at scale.

File
password_hasher_step3.py

New Functions
dictionary_attack_md5(target_hash: str) -> tuple[str | None, int, float]
Tries each word in a wordlist against a target MD5 hash. Returns the cracked password, number of attempts, and elapsed time in ms.
dictionary_attack_bcrypt(target_hash: bytes, wordlist: list) -> tuple[str | None, int, float]
Same attack against bcrypt. Capped at 5 attempts to keep the demo from running for minutes. The timing per attempt (~250ms) is the point.
brute_force_md5(target_hash, charset, max_length, max_attempts) -> tuple[str | None, int, float]
Exhaustive brute force —tries every character combination up to max_length. Uses itertools.product to generate candidates. Capped at 500k attempts for the demo.
estimate_bcrypt_brute_force(charset_size, password_length, ms_per_hash) -> dict
Projects brute force time against bcrypt without running it. At 250ms per hash, the math gets to centuries fast.
demonstrate_brute_force_attack()
Runs the full demo end to end across all four scenarios.

Sample Output
============================================================
STEP 3: Brute Force & Dictionary Attack Demo
============================================================

[1] Dictionary attack on MD5 hash of 'monkey123'
    Target: 4a81007b2c6c3d...
    CRACKED: 'monkey123' — 7 attempt(s) in 0.043ms

[2] Same dictionary attack on SHA-256
    Target: 5f4dcc3b5aa765...
    CRACKED: 'monkey123' — 7 attempt(s) in 0.021ms

[3] Brute force MD5 — target is short word 'cat'
    Trying all lowercase+digit combos up to 5 chars (cap 500k)...
    CRACKED: 'cat' after 731 attempts in 4.2ms
    Throughput: ~174,000 hashes/sec

[4] Dictionary attack on bcrypt (capped at 5 attempts)
    Not cracked after 5 attempt(s) — took 1284ms
    ~257ms per attempt (cost factor 12)

[5] Projected brute force time against bcrypt
    8-char lowercase only               208,827,064,576 combos → 1,660 years
    8-char lowercase+digits           2,821,109,907,456 combos → 22,427 years
    10-char mixed case+digits   839,299,365,868,340,736 combos → 6,676,563,294 years
    12-char full printable                    huge number combos → heat death

============================================================
SUMMARY
============================================================
  MD5/SHA-256 dictionary attack:  milliseconds
  MD5 brute force (short words):  milliseconds to seconds
  bcrypt dictionary (5 attempts): ~1-2 seconds for 5 guesses
  bcrypt brute force (8+ chars):  centuries to heat death of universe

  The cost factor (rounds=12) is the entire game.
  It doesn't make one hash slower — it makes billions of hashes impossible.


Key Concepts
Attack Type
MD5/SHA-256
bcrypt
Dictionary (common passwords)
Milliseconds
~250ms per guess
Brute force (short password)
Seconds
Centuries
Brute force (8+ char password)
Hours to days
Effectively impossible

Why MD5/SHA-256 fall so fast: throughput. A modern GPU can compute billions of MD5 hashes per second. Even a "strong" 8-character random password only has ~200 billion combinations — a GPU cluster cracks that in minutes.
Why bcrypt holds: the cost factor forces ~250ms per attempt regardless of hardware. You can't parallelize your way out of it. A billion guesses at 250ms each is 7,927 years.

Dependencies
Same as Steps 1 & 2 — no new installs needed.
bcrypt
hashlib    # stdlib
itertools  # stdlib
string     # stdlib


Next Step
Step 4: Timing Attack Demo — shows how naive string comparison (==) leaks information about the hash through response time differences, and why bcrypt's checkpw uses constant-time comparison to prevent it.



