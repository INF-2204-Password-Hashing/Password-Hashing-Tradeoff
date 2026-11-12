import time
import statistics
import subprocess
import re
from pathlib import Path

HASH_FILE = Path("hash.txt")

def time_hashing(fn, password:bytes, n_warmup: int = 50, n_runs: int = 250) -> dict:

    for _ in range(n_warmup):
        fn(password)

    times = []
    out = None
    for _ in range(n_runs):
        t0 = time.perf_counter()
        out = fn(password)
        t1 = time.perf_counter()
        times.append(t1 - t0)

    times_sorted = sorted(times)
    p95_idx = min(int(len(times_sorted) * 0.95), len(times_sorted) - 1)
 
    return {"median_s": statistics.median(times), "p95_s": times_sorted[p95_idx], "max_s": max(times), "last_hash": out}


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

def run_hashcat(hash_str: str, mode: str, mask: str, device: str = "2", runtime_cap_s: int = 60) -> dict:

    HASH_FILE.write_text(hash_str + "\n")

    cmd = [
        "hashcat", "-a", "3", "-m", 
        mode,
        str(HASH_FILE), 
        mask,
        "--potfile-disable",
        "-d", 
        device,
        "--self-test-disable",          # scrypt self test mismatch 
        f"--runtime={runtime_cap_s}",
    ]

    try:
        proc = subprocess.run(cmd, capture_output = True, text = True, timeout = runtime_cap_s + 30)
        output = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return {"guesses_per_sec": None, "recovered": False, "timed_out": True, "raw_output": ""}
    except FileNotFoundError:
        raise RuntimeError(
            "hashcat binary not found on PATH OMEGALUL"
        ) from None

    speed_match = re.search(r"Speed\.#\d+\.+:\s+([\d.]+)\s*(\w+)/s", output)
    recovered_match = re.search(r"Recovered\.+:\s+(\d+)/(\d+)", output)
    time_started_match = re.search(r"Time\.Started\.+:.*\((\d+)\s*secs?\)", output)

    guesses_per_sec = None
    if speed_match:
        value, unit = speed_match.groups()
        mult = {"H": 1, "kH": 1e3, "MH": 1e6, "GH": 1e9}.get(unit, 1)
        guesses_per_sec = float(value) * mult

    return {
        "guesses_per_sec": guesses_per_sec,
        "recovered": bool(recovered_match) and recovered_match.group(1) == recovered_match.group(2),
        "attack_duration_s": int(time_started_match.group(1)) if time_started_match else None,
        "timed_out": False,
        "raw_output": output,
    }

def run_hashcat_trials(hash_str: str, mode: str, mask: str, n_trials: int = 5, **kwargs) -> dict:
    speeds = []
    any_recovered = False
    
    for _ in range(n_trials):
        
        result = run_hashcat(hash_str, mode, mask, **kwargs)
        if result["guesses_per_sec"] is not None:
            speeds.append(result["guesses_per_sec"])
        
        any_recovered = any_recovered or result["recovered"]
 
    return {
        "mean_guesses_per_sec": statistics.mean(speeds) if speeds else None,
        "n_valid_trials": len(speeds),
        "recovered": any_recovered,
    }
