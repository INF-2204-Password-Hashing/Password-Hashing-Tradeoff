#!/usr/bin/env bash
#
# hash_generate.sh - Generate a hashcat-compatible hash file from plaintext passwords
#
# Usage:
#   ./hash_generate.sh -m <hashtype> -o <outfile> [-i <input_passwords_file> | -p <password>]
#
# Options:
#   -m <hashtype>   Hashcat hash type ID. Supported: 0 (MD5), 100 (SHA1),
#                   1400 (SHA256), 1700 (SHA512), 500 (md5crypt),
#                   1800 (sha512crypt), 3200 (bcrypt), 1000 (NTLM)
#   -o <outfile>    File to write generated hashes to
#   -i <infile>     File containing one plaintext password per line
#   -p <password>   Single plaintext password to hash (alternative to -i)
#
# Example:
#   ./hash_generate.sh -m 0 -i passwords.txt -o hashes.txt
#   ./hash_generate.sh -m 1800 -p "Summer2024!" -o hashes.txt
#
set -euo pipefail

HASHTYPE=""
OUTFILE=""
INFILE=""
SINGLEPW=""

usage() {
    grep '^#' "$0" | sed 's/^#//'
    exit 1
}

while getopts "m:o:i:p:h" opt; do
    case "$opt" in
        m) HASHTYPE="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        i) INFILE="$OPTARG" ;;
        p) SINGLEPW="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [[ -z "$HASHTYPE" || -z "$OUTFILE" ]]; then
    echo "Error: -m <hashtype> and -o <outfile> are required."
    usage
fi

if [[ -z "$INFILE" && -z "$SINGLEPW" ]]; then
    echo "Error: provide either -i <infile> or -p <password>."
    usage
fi

if [[ -n "$INFILE" && ! -f "$INFILE" ]]; then
    echo "Error: input file '$INFILE' not found."
    exit 1
fi

# Build the list of passwords to hash
TMP_PW_LIST=$(mktemp)
trap 'rm -f "$TMP_PW_LIST"' EXIT

if [[ -n "$INFILE" ]]; then
    cp "$INFILE" "$TMP_PW_LIST"
else
    echo "$SINGLEPW" > "$TMP_PW_LIST"
fi

> "$OUTFILE"

python3 - "$HASHTYPE" "$TMP_PW_LIST" "$OUTFILE" <<'PYEOF'
import sys, hashlib, crypt

hashtype, infile, outfile = sys.argv[1], sys.argv[2], sys.argv[3]

def md5crypt(pw):
    salt = crypt.mksalt(crypt.METHOD_MD5)
    return crypt.crypt(pw, salt)

def sha512crypt(pw):
    salt = crypt.mksalt(crypt.METHOD_SHA512)
    return crypt.crypt(pw, salt)

def bcrypt_hash(pw):
    try:
        import bcrypt
    except ImportError:
        sys.exit("Error: bcrypt mode requires 'pip install bcrypt'")
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def ntlm(pw):
    try:
        import passlib.hash as ph
        return ph.nthash.hash(pw)
    except ImportError:
        try:
            h = hashlib.new('md4', pw.encode('utf-16le'))
            return h.hexdigest()
        except ValueError:
            sys.exit("Error: NTLM mode requires 'pip install passlib' (MD4 not available in this OpenSSL build)")

handlers = {
    "0":    lambda pw: hashlib.md5(pw.encode()).hexdigest(),
    "100":  lambda pw: hashlib.sha1(pw.encode()).hexdigest(),
    "1400": lambda pw: hashlib.sha256(pw.encode()).hexdigest(),
    "1700": lambda pw: hashlib.sha512(pw.encode()).hexdigest(),
    "500":  md5crypt,
    "1800": sha512crypt,
    "3200": bcrypt_hash,
    "1000": ntlm,
}

if hashtype not in handlers:
    sys.exit(f"Error: unsupported hash type {hashtype}. "
              f"Supported: {', '.join(handlers.keys())}")

fn = handlers[hashtype]

with open(infile) as fin, open(outfile, "w") as fout:
    count = 0
    for line in fin:
        pw = line.rstrip("\n")
        if pw == "":
            continue
        fout.write(fn(pw) + "\n")
        count += 1

print(f"Wrote {count} hash(es) to {outfile}")
PYEOF