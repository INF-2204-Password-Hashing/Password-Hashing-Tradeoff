import csv
from pathlib import Path

from common import time_hashing, password_mask, run_hashcat_trials
#from common import run_hashcat
from algorithms import all_jobs

LATENCY_PASSWORD = b"N0&F1xfory0u"                  # reslistic password for timing
CRACK_PASSWORD = b"abc123"                          # small keypace used for hashing
CRACK_MASK = password_mask(CRACK_PASSWORD.decode())

CSV_PATH = Path("results.csv")
FIELDNAMES = [
    "label", 
    "hashcat_mode",
    "hash_median_s",
    "hash_p95_s",
    "hash_max_s",
    "mean_guesses_per_sec", 
    "recovered",
]

def main():
    jobs = all_jobs()
    n_done = 0

    with CSV_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        f.flush()

        for job in jobs:
            print(f"Running {job.label} ...", flush=True)

            latency = time_hashing(job.hash_for_timing, LATENCY_PASSWORD)

            crack_hash = job.hash_for_crack(CRACK_PASSWORD)
            crack = run_hashcat_trials(crack_hash, job.hashcat_mode, CRACK_MASK, n_trials = 5)
            result = run_hashcat_trials(crack_hash, job.hashcat_mode, CRACK_MASK, n_trials=5)

            row = {
                "label": job.label,
                "hashcat_mode": job.hashcat_mode,
                "hash_median_s": latency["median_s"],
                "hash_p95_s": latency["p95_s"],
                "hash_max_s": latency["max_s"],
                "mean_guesses_per_sec": crack["mean_guesses_per_sec"],
                "recovered": crack["recovered"],
            }

            writer.writerow(row)
            f.flush()
            n_done += 1

            #result = run_hashcat(crack_hash, "8900", CRACK_MASK)
            #print(result["raw_output"])

            print(
                f"hash_median={latency['median_s']*1e6:.2f}us  "
                f"guesses/sec={crack['mean_guesses_per_sec']}  "
                f"recovered={crack['recovered']}"
            )

    print(f"\nIt is done. Written{n_done}/{len(jobs)} rows to {CSV_PATH}")

if __name__ == "__main__":
        main()
