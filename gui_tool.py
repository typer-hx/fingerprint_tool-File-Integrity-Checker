#!/usr/bin/env python3
"""
gui_tool.py

Tkinter GUI wrapper for deterministic zipping, SHA256 and HMAC-SHA256 fingerprinting.
Save as gui_tool.py and run with: python gui_tool.py
"""

import os
import sys
import json
import hmac
import hashlib
import zipfile
import tempfile
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# --- Constants ---
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
DEFAULT_PERMISSIONS = 0o644
CHUNK_SIZE = 8192

# --- Core helpers (deterministic zip, hashing, manifest) ---
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

def write_manifest(path_to_manifest, kind, sha, hmac_hex):
    data = {"type": kind, "sha256": sha, "hmac": hmac_hex}
    Path(path_to_manifest).write_text(json.dumps(data))
    return str(path_to_manifest)

# --- GUI application ---
class FingerprintGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Fingerprint Tool")
        # set window icon (works when running script and when frozen by PyInstaller)
        try:
            if getattr(sys, "frozen", False):
                base_path = Path(sys._MEIPASS)
            else:
                base_path = Path(__file__).parent
            icon_path = base_path / "final image for icon.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        except Exception:
            pass

        self.geometry("820x560")
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill='both', expand=True)

        # Path selection
        path_frame = ttk.LabelFrame(frm, text="Select item")
        path_frame.pack(fill='x', pady=6)
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, width=80)
        path_entry.pack(side='left', padx=(6,4), pady=6)
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_path)
        browse_btn.pack(side='left', padx=4)
        clear_btn = ttk.Button(path_frame, text="Clear", command=lambda: self.path_var.set(''))
        clear_btn.pack(side='left', padx=4)

        # Mode selection
        type_frame = ttk.Frame(frm)
        type_frame.pack(fill='x', pady=4)
        ttk.Label(type_frame, text="Mode:").pack(side='left', padx=(6,4))
        self.mode_var = tk.StringVar(value='auto')
        for val, label in [('auto','Auto-detect'), ('file','File'), ('folder','Folder'), ('zip','Zip')]:
            ttk.Radiobutton(type_frame, text=label, variable=self.mode_var, value=val).pack(side='left', padx=6)

        # Secret and compression
        opts_frame = ttk.Frame(frm)
        opts_frame.pack(fill='x', pady=6)
        ttk.Label(opts_frame, text="HMAC secret:").pack(side='left', padx=(6,4))
        self.secret_var = tk.StringVar(value=os.environ.get('FINGERPRINT_SECRET',''))
        secret_entry = ttk.Entry(opts_frame, textvariable=self.secret_var, width=36, show='*')
        secret_entry.pack(side='left', padx=4)
        show_btn = ttk.Button(opts_frame, text="Show", width=6, command=self.toggle_secret)
        show_btn.pack(side='left', padx=4)
        ttk.Label(opts_frame, text="Compression:").pack(side='left', padx=(12,4))
        self.compress_var = tk.StringVar(value='stored')
        ttk.Combobox(opts_frame, textvariable=self.compress_var, values=['stored','deflated'], width=10).pack(side='left')

        # Actions
        action_frame = ttk.Frame(frm)
        action_frame.pack(fill='x', pady=6)
        run_btn = ttk.Button(action_frame, text="Run", command=self.run_fingerprint)
        run_btn.pack(side='left', padx=6)
        copy_btn = ttk.Button(action_frame, text="Copy Output", command=self.copy_output)
        copy_btn.pack(side='left', padx=6)
        clear_out_btn = ttk.Button(action_frame, text="Clear Output", command=lambda: self.output_text.delete('1.0','end'))
        clear_out_btn.pack(side='left', padx=6)
        help_btn = ttk.Button(action_frame, text="Help", command=self.show_help)
        help_btn.pack(side='right', padx=6)

        # Output area
        out_frame = ttk.LabelFrame(frm, text="Output")
        out_frame.pack(fill='both', expand=True, pady=6)
        self.output_text = scrolledtext.ScrolledText(out_frame, wrap='word', font=('Consolas',10))
        self.output_text.pack(fill='both', expand=True, padx=6, pady=6)

    def toggle_secret(self):
        current = self.secret_var.get()
        messagebox.showinfo("Secret value", f"Secret length: {len(current)} characters")

    def browse_path(self):
        mode = self.mode_var.get()
        if mode == 'folder':
            p = filedialog.askdirectory()
        elif mode == 'file' or mode == 'zip':
            p = filedialog.askopenfilename()
        else:
            p = filedialog.askopenfilename()
            if not p:
                p = filedialog.askdirectory()
        if p:
            self.path_var.set(p)

    def append(self, text):
        self.output_text.insert('end', text + '\n')
        self.output_text.see('end')

    def copy_output(self):
        txt = self.output_text.get('1.0','end').strip()
        if txt:
            self.clipboard_clear()
            self.clipboard_append(txt)
            messagebox.showinfo("Copied", "Output copied to clipboard.")
        else:
            messagebox.showinfo("No output", "There is no output to copy.")

    def show_help(self):
        help_text = (
            "How to use the Fingerprint Tool\n\n"
            "1. Select a File, Folder, or Zip using Browse. Let the mode be Auto-detect; if detection fails, switch the Mode manually.\n"
            "2. Set the HMAC secret (or set FINGERPRINT_SECRET env). Share the secret with the receiver via a secure out-of-band channel only.\n"
            "3. Choose Compression and click Run.\n"
            "4. After results you can verify interactively or save a JSON manifest.\n\n"
            "What is the HMAC secret and why it matters\n"
            "- HMAC is a keyed cryptographic checksum. The tool computes an HMAC-SHA256 using the secret you provide. "
            "The HMAC proves the file came from someone who knows the secret and that the file was not altered in transit. "
            "Do not include the secret in the same message or channel as the file or manifest.\n\n"
            "If you are the Sender\n"
            "- Set a fresh HMAC secret and share it with the Receiver using a secure out-of-band channel (for example, an encrypted message or a phone call). "
            "- Use the tool to create a deterministic zip for folders (recommended) or fingerprint the file directly. "
            "- **Important:** If the program produces a zip output, **send that zip file exactly as produced**. Do not rezip, modify, or unzip the archive before sending. "
            "The Receiver must verify the received zip file first; only unzip the archive after verification succeeds.\n\n"
            "If you are the Receiver\n"
            "- Obtain the HMAC secret from the Sender using the agreed secure channel. "
            "- Run this tool and open the received zip/file. Use the Verify option and paste the expected SHA256 and HMAC from the Sender (or use the manifest). "
            "- Only unzip or trust the contents after verification succeeds. If verification fails, do not unzip and contact the Sender to re-check the transfer and secret.\n\n"
            "Compression options\n"
            "- stored  : No compression. Files are placed into the ZIP unchanged. Fast and easiest to reproduce byte-for-byte; recommended for deterministic fingerprinting.\n"
            "- deflated: Uses the DEFLATE algorithm to compress entries. Produces smaller archives but requires CPU to compress and decompress. Use this when you want smaller transfer size; ensure both sender and receiver use the same compression option for verification.\n\n"
            "Security notes\n"
            "- Never send the HMAC secret together with the file or manifest on the same channel.\n"
            "- Change the secret for each transfer if you want one-time use.\n\n"
            "Non-technical launcher\n"
            "- Include run_tool.bat next to the exe to prompt for the secret before launching.\n\n"
            "Support and source\n"
            "- For further support and to view the source code, visit the GitHub page and search for the repository named \"fingerprint_tool\" at:\n"
            "  https://github.com/typer-hx\n"
        )
        messagebox.showinfo("Help", help_text)

    def run_fingerprint(self):
        self.output_text.delete('1.0','end')
        path = self.path_var.get().strip()
        if not path:
            messagebox.showerror("No path", "Please select a file or folder first.")
            return
        p = Path(path)
        if not p.exists():
            messagebox.showerror("Not found", f"Path does not exist: {path}")
            return
        secret = self.secret_var.get()
        if not secret:
            secret = os.environ.get('FINGERPRINT_SECRET','')
            if not secret:
                if not messagebox.askyesno("No secret", "No HMAC secret provided. Continue and be prompted to enter it?"):
                    return
                secret = self.simple_input("Enter HMAC secret (visible):")
                if secret is None:
                    return
        key = secret.encode('utf-8')
        compress = zipfile.ZIP_STORED if self.compress_var.get() == 'stored' else zipfile.ZIP_DEFLATED

        try:
            mode = self.mode_var.get()
            if mode == 'auto':
                if p.is_dir():
                    mode = 'folder'
                else:
                    is_zip = False
                    try:
                        with open(p, 'rb') as f:
                            header = f.read(4)
                            if header.startswith(b'PK\x03\x04'):
                                is_zip = True
                    except Exception:
                        pass
                    mode = 'zip' if is_zip else 'file'

            if mode == 'folder':
                self.append("Detected folder. Creating deterministic zip...")
                suggested = str(p.with_suffix('.zip').resolve())
                out_zip = filedialog.asksaveasfilename(initialfile=Path(suggested).name, defaultextension='.zip', filetypes=[('Zip files','*.zip')])
                if not out_zip:
                    self.append("Operation cancelled by user.")
                    return
                zip_path = deterministic_zip_from_folder(p, out_zip, compress=compress)
                sha = sha256_of_path(zip_path)
                mac = hmac_sha256_of_path(zip_path, key)
                self.append(f"Created zip at: {zip_path}")
                self.append(f"ZIP SHA256: {sha}")
                self.append(f"ZIP HMAC  : {mac}")
                self.post_actions(zip_path, "zip", sha, mac)

            elif mode == 'zip':
                self.append("Fingerprinting zip file directly...")
                sha = sha256_of_path(p)
                mac = hmac_sha256_of_path(p, key)
                self.append(f"ZIP SHA256: {sha}")
                self.append(f"ZIP HMAC  : {mac}")
                self.post_actions(str(p), "zip", sha, mac)

            elif mode == 'file':
                if messagebox.askyesno("Wrap file?", "Do you want to wrap the file into a deterministic zip before fingerprinting? (Yes = zip, No = raw file)"):
                    suggested = str(p.with_suffix('.zip').resolve())
                    out_zip = filedialog.asksaveasfilename(initialfile=Path(suggested).name, defaultextension='.zip', filetypes=[('Zip files','*.zip')])
                    if not out_zip:
                        self.append("Operation cancelled by user.")
                        return
                    zip_path = deterministic_zip_from_file(p, out_zip, arcname=p.name, compress=compress)
                    sha = sha256_of_path(zip_path)
                    mac = hmac_sha256_of_path(zip_path, key)
                    self.append(f"Created zip at: {zip_path}")
                    self.append(f"ZIP SHA256: {sha}")
                    self.append(f"ZIP HMAC  : {mac}")
                    self.post_actions(zip_path, "zip", sha, mac)
                else:
                    sha = sha256_of_path(p)
                    mac = hmac_sha256_of_path(p, key)
                    self.append(f"File SHA256: {sha}")
                    self.append(f"File HMAC  : {mac}")
                    self.post_actions(str(p), "file", sha, mac)
            else:
                self.append("Unknown mode.")
        except Exception as e:
            self.append("Error during processing:")
            self.append(traceback.format_exc())
            messagebox.showerror("Error", f"An error occurred: {e}")

    def post_actions(self, target_path, kind, sha, mac):
        if messagebox.askyesno("Verify now?", "Do you want to verify now by pasting expected SHA and HMAC?"):
            expected_sha = self.simple_input("Paste expected SHA256:")
            if expected_sha is None:
                self.append("Verification cancelled.")
            else:
                expected_hmac = self.simple_input("Paste expected HMAC (hex):")
                if expected_hmac is None:
                    self.append("Verification cancelled.")
                else:
                    sha_ok = (sha.lower() == expected_sha.strip().lower())
                    hmac_ok = (mac.lower() == expected_hmac.strip().lower())
                    if sha_ok and hmac_ok:
                        self.append("VERIFIED: both SHA256 and HMAC match.")
                        messagebox.showinfo("Verified", "Both SHA and HMAC match.")
                    else:
                        self.append("NOT VERIFIED:")
                        if not sha_ok:
                            self.append(f" - SHA mismatch. Computed: {sha}, Expected: {expected_sha}")
                        if not hmac_ok:
                            self.append(f" - HMAC mismatch. Computed: {mac}, Expected: {expected_hmac}")
                        messagebox.showwarning("Mismatch", "Computed values do not match expected values.")
        if messagebox.askyesno("Save manifest?", "Do you want to save a JSON manifest next to the produced file?"):
            manifest_path = str(Path(target_path).with_suffix('.json'))
            try:
                written = write_manifest(manifest_path, kind, sha, mac)
                self.append(f"Manifest written to: {written}")
                messagebox.showinfo("Manifest saved", f"Manifest saved to:\n{written}")
            except Exception as e:
                self.append(f"Failed to write manifest: {e}")
                messagebox.showerror("Write failed", f"Failed to write manifest: {e}")

    def simple_input(self, prompt):
        dlg = tk.Toplevel(self)
        dlg.title(prompt)
        dlg.transient(self)
        dlg.grab_set()
        ttk.Label(dlg, text=prompt).pack(padx=12, pady=(12,6))
        var = tk.StringVar()
        ent = ttk.Entry(dlg, textvariable=var, width=60)
        ent.pack(padx=12, pady=6)
        ent.focus_set()
        res = {'value': None}
        def on_ok():
            res['value'] = var.get()
            dlg.destroy()
        def on_cancel():
            dlg.destroy()
        btnf = ttk.Frame(dlg)
        btnf.pack(pady=(6,12))
        ttk.Button(btnf, text="OK", command=on_ok).pack(side='left', padx=6)
        ttk.Button(btnf, text="Cancel", command=on_cancel).pack(side='left', padx=6)
        self.wait_window(dlg)
        return res['value']

def main():
    app = FingerprintGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
