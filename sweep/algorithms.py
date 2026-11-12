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

def _sha256(pw: bytes) -> str:
    return hashlib.sha256(pw).hexdigest()
 
 
def sha256_jobs() -> list[Job]:
    return [Job("sha256", "1400", _sha256, _sha256)]

def all_jobs() -> list[Job]:
    return (
        sha256_jobs()
    )
