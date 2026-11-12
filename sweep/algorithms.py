import hashlib
import base64
from dataclasses import dataclass, field
from typing import Callable

import bcrypt
from argon2.low_level import hash_secret, Type

SALT = b"0123456789abcdef"  # irrelevant but fixed for reproducibility

@dataclass
class Job:
    label: str
    hashcat_mode: str | None
    hash_for_timing: Callable[[bytes], str]
    hash_for_crack: Callable[[bytes], str]


# SHA256

def _sha256(pw: bytes) -> str:
    return hashlib.sha256(pw).hexdigest()
 
 
def sha256_jobs() -> list[Job]:
    return [Job("sha256", "1400", _sha256, _sha256)]


# PBKDF2

def _pbkdf2_raw(pw: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw, SALT, iterations)
 
 
def _encode_pbkdf2_for_hashcat(pw: bytes, iterations: int) -> str:
    digest = _pbkdf2_raw(pw, iterations)
    return f"sha256:{iterations}:{base64.b64encode(SALT).decode()}:{base64.b64encode(digest).decode()}"
 
 
def pbkdf2_jobs() -> list[Job]:
    jobs = []
    for iters in [1_000, 10_000, 100_000, 310_000, 600_000]:
        jobs.append(Job(
            f"pbkdf2_iter{iters}",
            "10900",
            lambda pw, i=iters: _pbkdf2_raw(pw, i).hex(),
            lambda pw, i=iters: _encode_pbkdf2_for_hashcat(pw, i),
        ))
    return jobs
 
 
# bcrypt

def _bcrypt(pw: bytes, cost: int) -> str:
    return bcrypt.hashpw(pw, bcrypt.gensalt(rounds=cost)).decode()
 
 
def bcrypt_jobs() -> list[Job]:
    jobs = []
    for cost in [4, 6, 8, 10, 12, 14]:
        fn = lambda pw, c = cost: _bcrypt(pw, c)
        jobs.append(Job(f"bcrypt_cost{cost}", "3200", fn, fn))  # bcrypt's own format IS hashcat's
    return jobs
 
 
# scrypt (N is sweep, p and r cons)

def _scrypt_raw(pw: bytes, n: int, r: int, p: int) -> bytes:
    required_bytes = 128 * r * n
    maxmem = max(32 * 1024 * 1024, int(required_bytes * 1.5))
    return hashlib.scrypt(pw, salt = SALT, n = n, r = r, p = p, dklen = 32, maxmem = maxmem)
 
 
def _encode_scrypt_for_hashcat(pw: bytes, n: int, r: int, p: int) -> str:
    digest = _scrypt_raw(pw, n, r, p)
    return f"SCRYPT:{n}:{r}:{p}:{base64.b64encode(SALT).decode()}:{base64.b64encode(digest).decode()}"
 
 
def scrypt_jobs() -> list[Job]:
    jobs = []
    for n_exp in [10, 12, 14, 16, 18, 19]:
        n = 2 ** n_exp
        jobs.append(Job(
            f"scrypt_N2e{n_exp}",
            "8900",
            lambda pw, n=n: _scrypt_raw(pw, n, 8, 1).hex(),
            lambda pw, n=n: _encode_scrypt_for_hashcat(pw, n, 8, 1),
        ))
    return jobs
 

# Argon2id (mem cost x time cost, p is cons)
 
def _argon2id_raw(pw: bytes, mem_kib: int, time_cost: int, p: int) -> str:
    return hash_secret(pw, SALT, time_cost = time_cost, memory_cost = mem_kib, parallelism = p, hash_len = 32, type = Type.ID).decode()
 
 
def argon2id_jobs() -> list[Job]:
    jobs = []
    for m_exp in [12, 14, 16, 18]:
        mem_kib = 2 ** m_exp
        for t_cost in [1, 2, 3, 4]:
            fn = lambda pw, m=mem_kib, t=t_cost: _argon2id_raw(pw, m, t, 1)
            jobs.append(Job(f"argon2id_m2e{m_exp}_t{t_cost}", "34000", fn, fn))
    return jobs
 

def all_jobs() -> list[Job]:
    return (
        sha256_jobs()
        #+ pbkdf2_jobs()
        #+ bcrypt_jobs()
        #+ scrypt_jobs()
        #+ argon2id_jobs()
    )
