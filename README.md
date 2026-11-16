# Password-Hashing-Tradeoff

Measures defender-side hashing latency (CPU) and attacker-side cracking throughput (GPU, via hashcat) across five password and their parameter settings, and derives attacker advantage ratio and keyspace exhaustion time for each.

## Prerequisites
- Python 3.11+
- hashcat - NOT included, must be installed separately
  - Arch: sudo pacman -S hashcat 
  - Other distros / manual builds: https://hashcat.net/hashcat/
  - Confirm it's on your PATH: hashcat --version
- A working GPU driver, confirm hashcat can see your GPU before starting with 'hashcat -I'. If it doesn't list a GPU, fix that first

## Setup

```python
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
pip install -r requirements.txt
```


## Configuration — read this before running

All configuration lives in common.py, algorithms.py and main.py. Defaults on algorithm.py set for a full run of every algorithm; adjust before running a partial or quick-check sweep at the very bottom.

In main.py, each parameter setting calls hashcat n_trials times and averages the reported throughput:


```python
crack = run_hashcat_trials(crack_hash, job.hashcat_mode, CRACK_MASK, n_trials=5)
```

This number directly multiplies your total runtime. Each trial has a hashcat runtime capped at 60s (changeable in common.py). More trials = more reliable average = more time.

The runtime cap (common.py) stops the algorithm if it hasn't finished. With the defaults above  (5 * 60s) a single slow setting can take up to 5 minutes; across all 35 settings, most will finish in seconds, but the slow tail (high bcrypt cost, high Argon2id memory, high scrypt N) can bring the whole run up to SEVERAL HOURS. Plan accordingly.

Crack mask

```python 
CRACK_MASK = "?a?a?a?a?a?a?a?a"
```
```

```
is the current mask. It must match the length and character class assumptions, used in the exhaustion time formula (95^8 keyspace, if left as the 8-character full-printable-ASCII default). It is heavily advised that you choose a smaller password than the current random 8 character password, as well as commenting out the current CRACK_MASK and commenting in the automatic one for a smoother and faster experience, as even the pipeline testing of 'abc123' took about 3+ hours on the original test machine.
```

```
### Device selection


```python
"-d", "2",
````

Hardcoded into `common.py`. OpenCL device index that worked on the original test machine - confirm this is correct on your machine with hashcat -I before running; a GPU with a different backend arrangement (e.g. no separate CUDA/OpenCL split) may need a different number or no -d flag at all.

## Running it

Quick check: in `algorithms.py``, comment out all algorithms except for SHA-256, and then run: `python3 main.py`.

This should finish fairly quickly and produce a .csv file with only one relevant row. If it work comment in the rest and run the same way.

Progress prints to the terminal after each setting completes. Don't close the terminal or interrupt the process, as the results are written incrementally to 'results.csv' after each setting, and closing the terminal will kill the process.

If for some reason the `guesses/sec` return as empty, uncomment the debug lines and try the relevant algorithms again. This will print the full hashcat output and shed light on the issues.

## Output
- results.csv — one row per (algorithm, parameter setting): latency (median/p95/max), mean guesses/sec, and whether the crack-validation password was recovered.
- hash.txt — scratch file, overwritten each hashcat call. Not meaningful after the run finishes.

## Known limitations (see report for full discussion)
- scrypt sweep is capped at N=2^19 on the attacker side — hashcat's hash parser rejects N=2^20 
- Results are specific to the test machine's single consumer GPU; absolute throughput values won't transfer to other hardware, though the relative ranking between algorithms is expected to.
