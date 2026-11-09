import hashlib
import time
import statistics
import subprocess
import re
import csv
from pathlib import Path

# hashing latency
LATENCY_TEST_PASSWORD = b"N0&F1xfory0u"  # fixed test password

def hash_sha256(password: bytes) -> str:
    return hashlib.sha256(password).hexdigest()

def time_hashing(fn, password: bytes, n_warmup = 50, n_runs = 250) -> dict:
    for _ in range(n_warmup):
        fn(password)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        out = fn(password)
        t1 = time.perf_counter()
        times.append(t1 - t0)

    return {"median_s": statistics.median(times), "max_s": max(times), "last_hash": out}

# cracking latency (small password so it actually finishes KEKL)

def password_mask(password:str) -> str:     # automatic masking
    mask_parts = []
    for ch in password:
        if ch.islower():
            mask_parts.append("?l")
        elif ch.isupper():
            mask_parts.append("?u")
        elif ch.isdigit():
            mask_parts.append("?d")
        else:
            mask_parts.append("?s")         # may not work with certain symbols
    return "".join(mask_parts)

CRACK_PASSWORD = b"abc123"
#CRACK_MASK = "?l?l?l?d?d?d"
CRACK_MASK = password_mask(CRACK_PASSWORD.decode())
SHA256_HASHCAT_MODE = "1400"

def time_cracking(hash_hex: str, mode: str, mask: str) -> dict:
    hash_file = Path("hash.txt")
    hash_file.write_text(hash_hex + "\n")

    cmd = [
        "hashcat", "-a", "3", "-m", mode,
        str(hash_file), mask, "--potfile-disable",
        "-d", "2",
    ]

    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output = True, text = True)
    t1 = time.perf_counter()
    wall_time = t1 - t0

    #output = proc.stdout + "\n" + proc.stder
    #print("----- RAW HASHCAT OUTPUT -----")
    #print(output)
    #print("-------------------------------")

    output = proc.stdout
    speed_match = re.search(r"Speed\.#\d+\.+:\s+([\d.]+)\s*(\w+)/s", output)
    recovered_match = re.search(r"Recovered\.+:\s+(\d+)/(\d+)", output)

    guesses_per_sec = None
    if speed_match:
        value, unit = speed_match.groups()
        mult = {"H": 1, "kH": 1e3, "MH": 1e6, "GH": 1e9}.get(unit, 1)
        guesses_per_sec = float(value) * mult

    recovered = bool(recovered_match) and recovered_match.group(1) == recovered_match.group(2)

    return {
        "wall_time_s": wall_time,
        "guesses_per_sec": guesses_per_sec,
        "recovered": recovered,
    }

# run both, store info
latency_result = time_hashing(hash_sha256, LATENCY_TEST_PASSWORD)
crack_hash = hash_sha256(CRACK_PASSWORD)
crack_result = time_cracking(crack_hash, SHA256_HASHCAT_MODE, CRACK_MASK)

print("Hashing median:", latency_result["median_s"] * 1e6, "µs")
print("Crack wall time:", crack_result["wall_time_s"], "s")
print("Crack guesses/sec:", crack_result["guesses_per_sec"])
print("Recovered:", crack_result["recovered"])

with open("results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["algorithm", "hash_median_s", "hash_max_s", "crack_wall_time_s", "guesses_per_sec", "recovered"])
    writer.writerow([
        "sha256",
        latency_result["median_s"],
        latency_result["max_s"],
        crack_result["wall_time_s"],
        crack_result["guesses_per_sec"],
        crack_result["recovered"],
    ])
