# Fingerprint Tool – File Integrity Checker

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Security](https://img.shields.io/badge/Integrity-SHA256%20%7C%20HMAC--SHA256-green)
![License](https://img.shields.io/badge/License-SF--NC-blue)

Deterministic zipping and verification utility that produces reproducible ZIP archives and cryptographic fingerprints (**SHA256** and **HMAC-SHA256**).

The project provides:

• A **GUI tool for general users**  
• A **CLI tool for automation and scripting**

Repository:

https://github.com/typer-hx/fingerprint_tool-File-Integrity-Checker.git

---

# One-line Summary

Create deterministic ZIP archives and verify them using **SHA256 and HMAC-SHA256** to ensure the file has not been modified.

---

# Features

• Deterministic ZIP creation  
• SHA256 hashing for integrity verification  
• HMAC-SHA256 authenticated hashing  
• Automatic folder → deterministic ZIP conversion  
• CLI automation support  
• GUI interface for non-technical users  
• JSON manifest export  
• Interactive verification mode  
• Secure workflow for sender and receiver  

---

# Why Deterministic Zipping?

Normal ZIP tools may produce **different binary outputs** even when the files inside are identical.

Reasons include:

• timestamps  
• metadata  
• file ordering  

This tool eliminates those differences by:

• sorting files before zipping  
• fixing timestamps  
• fixing permissions  

Result:

**same input → identical ZIP → identical hash**

This makes cryptographic verification reliable.

---

# Repository Structure

```
fingerprint_tool-File-Integrity-Checker/
│
├─ fingerprint_tool_cli.py
├─ gui_tool.py
├─ sample_manifest.json
├─ CHECKSUMS.txt
├─ LICENSE
└─ README.md
```

---

# Installation

## Requirements

Python **3.8 or newer**

---

## Clone the Repository

```bash
git clone https://github.com/typer-hx/fingerprint_tool-File-Integrity-Checker.git
cd fingerprint_tool-File-Integrity-Checker
```

(Optional virtual environment)

```bash
python -m venv .venv
.venv\Scripts\activate
```

---

# CLI Usage

### Fingerprint a file

```bash
python fingerprint_tool_cli.py file.txt
```

---

### Fingerprint a folder

```bash
python fingerprint_tool_cli.py folder_name
```

The folder will automatically be converted into a **deterministic ZIP**.

---

### Wrap file into deterministic zip

```bash
python fingerprint_tool_cli.py file.txt --zip-files
```

---

### Specify output location

```bash
python fingerprint_tool_cli.py folder_name --out output.zip
```

---

# Setting HMAC Secret

Linux / macOS

```bash
export FINGERPRINT_SECRET=mysecret
```

Windows CMD

```bash
set FINGERPRINT_SECRET=mysecret
```

The secret must be shared securely with the receiver.

---

# GUI Usage

Run the GUI:

```bash
python gui_tool.py
```

Steps:

1. Select a file or folder  
2. Enter the HMAC secret  
3. Click **Run**  
4. The tool generates SHA256 and HMAC values  

Optional actions:

• verify fingerprints  
• save JSON manifest  

---

# Example Manifest

```json
{
"type": "zip",
"filename": "package.zip",
"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
"hmac": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
}
```

---

# Example Workflow

### Sender

1. Generate ZIP and fingerprints
2. Send ZIP file to receiver
3. Send SHA256 and HMAC values
4. Share secret through secure channel

### Receiver

1. After receiving the secure HMAC code, Runs verification
2. Compare hashes
3. If verified → unzip safely

---

# Manual Verification Commands

PowerShell

```bash
Get-FileHash package.zip -Algorithm SHA256
```

Windows CMD

```bash
certutil -hashfile package.zip SHA256
```

OpenSSL HMAC example

```bash
openssl dgst -sha256 -hmac "secret" package.zip
```

---

# Building the Windows Executable

You can build the GUI executable using **PyInstaller**.

Install PyInstaller:

```bash
pip install pyinstaller
```

Build the executable:

```bash
pyinstaller --onefile --windowed gui_tool.py
```

The executable will appear inside:

```
dist/gui_tool.exe
```

Upload the EXE to **GitHub Releases** instead of committing it to the repository.

---

# Generating CHECKSUMS.txt

Example:

```bash
certutil -hashfile dist\gui_tool.exe SHA256
```

Example format:

```
gui_tool.exe  SHA256  <hash>
fingerprint_tool_cli.py  SHA256  <hash>
```

---

# Security Best Practices

• Never send the **HMAC secret together with the file**  
• Share secrets via **secure channel**  
• Always verify hashes before extracting files  
• Do not modify the produced ZIP before sending  
• Generate a new secret for each transfer if possible  

---

# Contributing

Contributions are welcome.

Steps:

1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Open a Pull Request

Repository:

https://github.com/typer-hx/fingerprint_tool-File-Integrity-Checker

---

# Disclaimer

This tool is designed for **file integrity verification** and **secure file transfer workflows**.

It does **not replace full cryptographic signing systems** such as GPG or code signing.

---

# License

Student-First Non-Commercial License (SF-NC)

Commercial use requires permission.

---

# Author

Aditya  
https://github.com/typer-hx
