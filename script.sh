#!/usr/bin/env bash
#
# hashcat_run.sh - Wrapper script for hashcat
#
# Usage:
#   ./hashcat_run.sh -m <hashtype> -f <hashfile> [-w] [-b] [-c <charset>] [-l <max_len>]
#
# Options:
#   -m <hashtype>   Hashcat hash type ID (e.g. 0 = MD5, 1000 = NTLM, 1800 = sha512crypt)
#   -f <hashfile>   Path to file containing the hash(es) to crack
#   -w              Run dictionary attack using rockyou.txt (with best64 rules)
#   -b              Run brute-force (mask) attack
#   -c <charset>    Custom charset for brute-force (default: ?a = all printable)
#   -l <max_len>    Max password length for brute-force (default: 8)
#
# Example:
#   ./hashcat_run.sh -m 0 -f hashes.txt -w
#   ./hashcat_run.sh -m 1000 -f hashes.txt -b -l 6
#   ./hashcat_run.sh -m 1800 -f hashes.txt -w -b
#
set -euo pipefail

ROCKYOU="/cvlknight/INF-2204/Password-Hashing-Tradeoff/rockyou.txt"
RULES="/cvlknight/INF-2204/Password-Hashing-Tradeoff/rules/best66.rule"
CHARSET="?a"
MAXLEN=8
DO_WORDLIST=1
DO_BRUTE=1
HASHTYPE="SHA-256"
HASHFILE=""

usage() {
    grep '^#' "$0" | sed 's/^#//'
    exit 1
}

while getopts "m:f:wbc:l:h" opt; do
    case "$opt" in
        m) HASHTYPE="$OPTARG" ;;
        f) HASHFILE="$OPTARG" ;;
        w) DO_WORDLIST=1 ;;
        b) DO_BRUTE=1 ;;
        c) CHARSET="$OPTARG" ;;
        l) MAXLEN="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$HASHTYPE" || -z "$HASHFILE" ]]; then
    echo "Error: -m <hashtype> and -f <hashfile> are required."
    usage
fi

if [[ ! -f "$HASHFILE" ]]; then
    echo "Error: hash file '$HASHFILE' not found."
    exit 1
fi

if [[ "$DO_WORDLIST" -eq 0 && "$DO_BRUTE" -eq 0 ]]; then
    echo "Error: choose at least one attack mode (-w for wordlist, -b for brute-force)."
    usage
fi

echo "=== Hashcat run: hash type $HASHTYPE, file $HASHFILE ==="

if [[ "$DO_WORDLIST" -eq 1 ]]; then
    if [[ ! -f "$ROCKYOU" ]]; then
        echo "Error: rockyou wordlist not found at $ROCKYOU"
        echo "Set the ROCKYOU variable at the top of this script to its correct path."
        exit 1
    fi
    echo "--- Dictionary attack (rockyou.txt) ---"
    if [[ -f "$RULES" ]]; then
        hashcat -m "$HASHTYPE" -a 0 "$HASHFILE" "$ROCKYOU" -r "$RULES" --potfile-disable
    else
        hashcat -m "$HASHTYPE" -a 0 "$HASHFILE" "$ROCKYOU" --potfile-disable
    fi
fi

if [[ "$DO_BRUTE" -eq 1 ]]; then
    echo "--- Brute-force attack (mask, up to length $MAXLEN, charset $CHARSET) ---"
    for ((len=1; len<=MAXLEN; len++)); do
        mask=$(printf "$CHARSET%.0s" $(seq 1 "$len"))
        echo "Trying length $len..."
        hashcat -m "$HASHTYPE" -a 3 "$HASHFILE" "$mask" --potfile-disable
    done
fi

echo "=== Done. Showing cracked results (if any): ==="
hashcat -m "$HASHTYPE" "$HASHFILE" --show --potfile-disable || true