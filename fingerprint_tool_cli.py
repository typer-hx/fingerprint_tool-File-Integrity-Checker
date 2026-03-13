#!/usr/bin/env python3
"""
fingerprint_tool.py

Usage examples:
  python fingerprint_tool.py /path/to/item
  python fingerprint_tool.py /path/to/item --zip-files
  python fingerprint_tool.py /path/to/item --secret-file /path/to/secret.txt
  python fingerprint_tool.py /path/to/item --out /path/to/save.zip

Behavior:
 - If input is a file: by default compute SHA256 and HMAC on file bytes.
   If --zip-files is set, wrap the file into a deterministic zip and fingerprint that zip.
 - If input is a folder: create a deterministic zip, ask where to save it (unless --out provided),
   then compute SHA256 and HMAC on the zip bytes.
 - If input is a zip: compute SHA256 and HMAC on the zip bytes directly.
 - After computing SHA and HMAC the script will offer an interactive verify prompt:
   the user can paste expected SHA and HMAC to compare immediately.
 - Optionally the script can write a small JSON manifest next to the produced zip/file.
"""

"""
See, HOW TO USE THIS code in cmd, this is the initial code, it will do everything but will not give option for verification.
So, the user have to use another platform or have to do mannual verification.

See, First it is recommended that the file folder which the user wants to get the SHA and HMAC codes should be in the same folder for ease.

Firstly, the user needs to locate the path where this py script is saved:: example:"D:\PythonProgramming\File Integrity Checker\fingerprint_tool_initial.py"
Then they can bring the target file/folder/zip folder on the same location:: example:"D:\PythonProgramming\File Integrity Checker\target.extension"(let's say a .txt file or a .zip folder)
OR
they can save a normal folder on the same location:: example"D:\PythonProgramming\File Integrity Checker\target_folder"


Then they have to type this code in the cmd(administrator mode recommended, it will also work in non-administrator mode but if any issue rises, then try the administrator mode)::

1>Locate the cmd in the folder:
pushd "D:\PythonProgramming\File Integrity Checker"
2>Have to set a HMAC code:(See, this HMAC code needs to be shared with the receiver through a secured channel. And you can set a new HMAC code everytime)
Then you can set the HMAC code for example:
set FINGERPRINT_SECRET=xyz
#you can write anything in place of 'xyz'
3>Then, you are all set and have to generate the SHA and HMAC codes:
for example we are taking 3 types:
a)A file::ex:(target.txt)
b)A folder::ex:(target_folder)
c)A zip folder(treated as a file only)::ex:(target.zip)
    a) In case of a single file:-
    python fingerprint_tool.py "target.txt" #CODE
    The programme will not do any extra work and will just give the SHA and HMAC codes

    b)In case of a folder:-
    python fingerprint_tool.py "target_folder" #CODE
    As, the folder is unzipped, so this script needs to zip the folder, so it will ask for zipping and also tell the necessary things.

    c)In case of a zip folder:-
    python fingerprint_tool.py "test_folder_manual.zip" #CODE
    No extra steps and the script will provide the SHA and Hmac codes.

4>This script auto provides the verification and a option to save JSON manifest.

5>Recommend you to change the FINGERPRINT SECRET EVERYTIME.

6>You can send the SHA and HMAC codes(GENERATED ONES).
BUT, DO NOT SEND THE FINGERPRINT_SECRET CODE(S) FROM UNSAFE CHANNEL.

I RECOMMEND YOU TO SEND THE SHA AND HMAC AND THE FINGERPRINT_SECRECT CODES FROM A SECURE CHANNEL.

"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

# Deterministic zip constants
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)  # stable timestamp for ZipInfo (year,month,day,hour,min,sec)
DEFAULT_PERMISSIONS = 0o644
CHUNK_SIZE = 8192


def read_secret(args):
    # Priority: --secret, --secret-file, env FINGERPRINT_SECRET, prompt
    if args.secret:
        return args.secret.encode('utf-8')
    if args.secret_file:
        p = Path(args.secret_file)
        if p.is_file():
            return p.read_bytes().strip()
    env = os.environ.get('FINGERPRINT_SECRET')
    if env:
        return env.encode('utf-8')
    # Prompt user
    try:
        import getpass
        s = getpass.getpass("Enter HMAC secret (input hidden): ")
        return s.encode('utf-8')
    except Exception:
        print("Unable to read secret. Exiting.", file=sys.stderr)
        sys.exit(1)


def sha256_of_path(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hmac_sha256_of_path(path, key):
    hm = hmac.new(key, digestmod=hashlib.sha256)
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hm.update(chunk)
    return hm.hexdigest()


def deterministic_zip_from_folder(folder_path, out_zip_path, compress=zipfile.ZIP_STORED):
    """
    Create a deterministic zip of folder_path at out_zip_path.
    - Sort files by relative path
    - Use fixed timestamp and fixed permission bits
    - Stream file contents into zip to avoid large memory usage
    """
    folder_path = Path(folder_path)
    entries = []
    for root, _, files in os.walk(folder_path):
        for fname in files:
            full = Path(root) / fname
            rel = full.relative_to(folder_path).as_posix()
            entries.append((rel, full))
    entries.sort(key=lambda x: x[0])
    out_zip_path = Path(out_zip_path)
    out_zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip_path, 'w') as zf:
        for rel, full in entries:
            zi = zipfile.ZipInfo(rel)
            zi.date_time = FIXED_DATE_TIME
            zi.compress_type = compress
            zi.external_attr = (DEFAULT_PERMISSIONS << 16)
            with zf.open(zi, 'w') as dest, open(full, 'rb') as src:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    dest.write(chunk)
    return str(out_zip_path)


def deterministic_zip_from_file(file_path, out_zip_path, arcname=None, compress=zipfile.ZIP_STORED):
    """
    Wrap a single file into a deterministic zip.
    arcname defaults to the file's basename.
    """
    file_path = Path(file_path)
    arcname = arcname or file_path.name
    out_zip_path = Path(out_zip_path)
    out_zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip_path, 'w') as zf:
        zi = zipfile.ZipInfo(arcname)
        zi.date_time = FIXED_DATE_TIME
        zi.compress_type = compress
        zi.external_attr = (DEFAULT_PERMISSIONS << 16)
        with zf.open(zi, 'w') as dest, open(file_path, 'rb') as src:
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                dest.write(chunk)
    return str(out_zip_path)


def ask_save_location(default_suggested):
    print("Please provide a full path where the new zip should be saved.")
    print(f"Press Enter to save here: {default_suggested}")
    resp = input("Save path: ").strip()
    if not resp:
        return default_suggested
    return resp


def write_manifest(path_to_manifest, kind, sha, hmac_hex):
    data = {"type": kind, "sha256": sha, "hmac": hmac_hex}
    Path(path_to_manifest).write_text(json.dumps(data))
    return str(path_to_manifest)


def interactive_verify_prompt(computed_sha, computed_hmac):
    """
    Ask the user if they want to verify now. If yes, prompt for expected sha and hmac,
    compare and print result.
    """
    resp = input("Do you want to verify now by pasting expected SHA and HMAC? (y/N): ").strip().lower()
    if resp != 'y':
        return
    expected_sha = input("Paste expected SHA256: ").strip().lower()
    expected_hmac = input("Paste expected HMAC (hex): ").strip().lower()
    sha_ok = (computed_sha.lower() == expected_sha)
    hmac_ok = (computed_hmac.lower() == expected_hmac)
    if sha_ok and hmac_ok:
        print("VERIFIED: both SHA256 and HMAC match.")
    else:
        print("NOT VERIFIED:")
        if not sha_ok:
            print(f" - SHA mismatch. Computed: {computed_sha}, Expected: {expected_sha}")
        if not hmac_ok:
            print(f" - HMAC mismatch. Computed: {computed_hmac}, Expected: {expected_hmac}")


def maybe_write_manifest_prompt(target_path, kind, sha, mac):
    """
    Offer to write a JSON manifest next to the target (zip or file).
    """
    resp = input("Do you want to save a JSON manifest next to the produced file? (y/N): ").strip().lower()
    if resp != 'y':
        return
    manifest_path = str(Path(target_path).with_suffix('.json'))
    try:
        written = write_manifest(manifest_path, kind, sha, mac)
        print("Manifest written to:", written)
    except Exception as e:
        print("Failed to write manifest:", e, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Fingerprint files and folders with SHA256 and HMAC-SHA256.")
    parser.add_argument("path", help="Path to file, folder, or zip")
    parser.add_argument("--zip-files", action="store_true", help="Wrap single files into deterministic zip before fingerprinting")
    parser.add_argument("--out", help="If creating a zip, save it to this path (optional)")
    parser.add_argument("--secret", help="HMAC secret string (not recommended on CLI)")
    parser.add_argument("--secret-file", help="File containing HMAC secret")
    parser.add_argument("--compress", choices=["stored", "deflated"], default="stored", help="Compression method for deterministic zip")
    args = parser.parse_args()

    p = Path(args.path)
    if not p.exists():
        print("Error: path does not exist.", file=sys.stderr)
        sys.exit(2)

    key = read_secret(args)
    compress = zipfile.ZIP_STORED if args.compress == "stored" else zipfile.ZIP_DEFLATED

    try:
        if p.is_dir():
            # Folder: create deterministic zip
            suggested = str(p.with_suffix('.zip').resolve())
            out_zip = args.out or ask_save_location(suggested)
            print("\nI detected you uploaded an unzipped folder.")
            print("I will create a deterministic zip of the folder and compute SHA256 and HMAC from that zip.")
            print("Please send the resulting zip directly to the receiver without unzipping it. The receiver should verify the zip using the same tool and only unzip after verification succeeds.\n")
            try:
                zip_path = deterministic_zip_from_folder(p, out_zip, compress=compress)
            except Exception as e:
                print("Failed to create deterministic zip:", e, file=sys.stderr)
                out_zip = ask_save_location(suggested)
                zip_path = deterministic_zip_from_folder(p, out_zip, compress=compress)
            sha = sha256_of_path(zip_path)
            mac = hmac_sha256_of_path(zip_path, key)
            print("Created zip at:", zip_path)
            print("ZIP SHA256:", sha)
            print("ZIP HMAC :", mac)

            # Interactive verify and optional manifest
            interactive_verify_prompt(sha, mac)
            maybe_write_manifest_prompt(zip_path, "zip", sha, mac)
            sys.exit(0)

        # If path is a file
        if p.is_file():
            # Detect if it's a zip by magic header
            is_zip = False
            try:
                with open(p, 'rb') as f:
                    header = f.read(4)
                    if header.startswith(b'PK\x03\x04'):
                        is_zip = True
            except Exception:
                pass

            if is_zip:
                # Fingerprint zip directly
                sha = sha256_of_path(p)
                mac = hmac_sha256_of_path(p, key)
                print("Input is a zip file.")
                print("ZIP SHA256:", sha)
                print("ZIP HMAC :", mac)

                interactive_verify_prompt(sha, mac)
                maybe_write_manifest_prompt(p, "zip", sha, mac)
                sys.exit(0)
            else:
                if args.zip_files:
                    # Wrap file into deterministic zip
                    suggested = str(p.with_suffix('.zip').resolve())
                    out_zip = args.out or ask_save_location(suggested)
                    try:
                        zip_path = deterministic_zip_from_file(p, out_zip, arcname=p.name, compress=compress)
                    except Exception as e:
                        print("Failed to create deterministic zip for file:", e, file=sys.stderr)
                        out_zip = ask_save_location(suggested)
                        zip_path = deterministic_zip_from_file(p, out_zip, arcname=p.name, compress=compress)
                    sha = sha256_of_path(zip_path)
                    mac = hmac_sha256_of_path(zip_path, key)
                    print("Created zip at:", zip_path)
                    print("ZIP SHA256:", sha)
                    print("ZIP HMAC :", mac)

                    interactive_verify_prompt(sha, mac)
                    maybe_write_manifest_prompt(zip_path, "zip", sha, mac)
                    sys.exit(0)
                else:
                    # Fingerprint file bytes directly
                    sha = sha256_of_path(p)
                    mac = hmac_sha256_of_path(p, key)
                    print("File SHA256:", sha)
                    print("File HMAC :", mac)

                    interactive_verify_prompt(sha, mac)
                    maybe_write_manifest_prompt(p, "file", sha, mac)
                    sys.exit(0)

    except Exception as e:
        # Coverup behavior: if anything unexpected happens, suggest zipping and ask where to save
        print("The program encountered an error while generating consistent codes:", e, file=sys.stderr)
        print("As a fallback, I can create a deterministic zip of the item and compute codes from that zip.")
        suggested = str(p.with_suffix('.zip').resolve())
        out_zip = args.out or ask_save_location(suggested)
        try:
            if p.is_dir():
                zip_path = deterministic_zip_from_folder(p, out_zip, compress=compress)
            else:
                zip_path = deterministic_zip_from_file(p, out_zip, arcname=p.name, compress=compress)
            sha = sha256_of_path(zip_path)
            mac = hmac_sha256_of_path(zip_path, key)
            print("Created zip at:", zip_path)
            print("ZIP SHA256:", sha)
            print("ZIP HMAC :", mac)

            interactive_verify_prompt(sha, mac)
            maybe_write_manifest_prompt(zip_path, "zip", sha, mac)
            sys.exit(0)
        except Exception as e2:
            print("Failed to create fallback zip:", e2, file=sys.stderr)
            print("Unable to produce consistent codes. Please check file permissions and try again.")
            sys.exit(3)


if __name__ == "__main__":
    main()
