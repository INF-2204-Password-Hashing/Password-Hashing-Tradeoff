import hashlib
import time
import statistics

TEST_PASSWORD = b"N0&F1xfory0u"  # fixed test password

def hash_sha256(pw: bytes) -> str:
    return hashlib.sha256(pw).hexdigest()

# warm up, don't save results
for _ in range(50):
    hash_sha256(TEST_PASSWORD)

# timings
times = []
for _ in range(250):
    t0 = time.perf_counter()
    result = hash_sha256(TEST_PASSWORD)
    t1 = time.perf_counter()
    times.append(t1 - t0)

print("Hash output:", result)
print(f"Median: {statistics.median(times)*1e6:.2f} µs")
print(f"Max:    {max(times)*1e6:.2f} µs")
