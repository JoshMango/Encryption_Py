"""
main.py
-------
Encryption & Decryption Demo App (Tkinter desktop GUI)

Run with:   python main.py

A simple, self-contained desktop application that lets a user:
    - Type a message and a password, then Encrypt it (AES-256-CBC + PBKDF2).
    - Paste an encrypted message and its password, then Decrypt it back.
    - See friendly error messages for bad input, wrong passwords, or
      corrupted/tampered ciphertext (graceful error handling).
    - Load a built-in sample so the app can be demoed with one click.
    - Copy results to the clipboard for easy testing.

No third-party GUI framework is required -- everything here uses Python's
built-in `tkinter`, so the only external dependency is the `cryptography`
package (see requirements.txt).
"""

# !!!!!   THIS FILE IS FOR UI AND UX PURPOSES ONLY, THE ACTUAL ESSENTIAL CRYPTOGRAPHY FUNCTIONS ARE IN crypto_utils.py  !!!!!!

import tkinter as tk
from tkinter import ttk, messagebox

from crypto_utils import encrypt_text, decrypt_text, CryptoError

APP_TITLE = "Encryption & Decryption Demo"
BG = "#111119"
PANEL_BG = "#222228"
ACCENT = "#126c19"
ACCENT_DARK = "#006400"
TEXT_LIGHT = "#2bd347"
SUBTLE = "#227a26"
SUCCESS = "#00ff73"
ERROR = "#e42c2c"
FONT_FAMILY = "Segoe UI"

SAMPLE_MESSAGE = "The treasure is buried under the old oak tree at midnight."
SAMPLE_PASSWORD = "CorrectHorseBatteryStaple"


class RoundedButton(tk.Button):
    """A tk.Button pre-styled to look flat / modern and to show a hover effect."""

    def __init__(self, master, bg=ACCENT, hover=ACCENT_DARK, fg="white", **kwargs):
        super().__init__(
            master,
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=14,
            pady=8,
            font=(FONT_FAMILY, 10, "bold"),
            cursor="hand2",
            **kwargs,
        )
        self._bg = bg
        self._hover = hover
        self.bind("<Enter>", lambda e: self.config(bg=self._hover))
        self.bind("<Leave>", lambda e: self.config(bg=self._bg))


class EncryptDecryptApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("880x640")
        self.minsize(760, 560)
        self.configure(bg=BG)

        self._build_style()
        self._build_header()
        self._build_body()
        self._build_status_bar()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=PANEL_BG,
            foreground=TEXT_LIGHT,
            padding=(20, 10),
            font=(FONT_FAMILY, 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", ACCENT)],
            foreground=[("selected", "white")],
        )

    def _build_header(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=24, pady=(20, 10))

        tk.Label(
            header,
            text="🔐  Encryption & Decryption Program",
            bg=BG,
            fg=TEXT_LIGHT,
            font=(FONT_FAMILY, 18, "bold"),
        ).pack(anchor="w")

        tk.Label(
            header,
            text="Algorithm: AES-256 (CBC mode) with PBKDF2-HMAC-SHA256 password-based key derivation",
            bg=BG,
            fg=SUBTLE,
            font=(FONT_FAMILY, 10),
        ).pack(anchor="w", pady=(2, 0))

    def _build_body(self):
        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=24, pady=10)

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)

        encrypt_tab = tk.Frame(notebook, bg=BG)
        decrypt_tab = tk.Frame(notebook, bg=BG)
        notebook.add(encrypt_tab, text="  Encrypt  ")
        notebook.add(decrypt_tab, text="  Decrypt  ")

        self._build_encrypt_tab(encrypt_tab)
        self._build_decrypt_tab(decrypt_tab)

    # ---- Encrypt tab ---------------------------------------------------
    def _build_encrypt_tab(self, parent):
        pad = {"padx": 4, "pady": (12, 4)}

        tk.Label(parent, text="Plaintext message", bg=BG, fg=TEXT_LIGHT,
                 font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", **pad)
        self.enc_input = self._make_textbox(parent, height=6)

        tk.Label(parent, text="Password / Key", bg=BG, fg=TEXT_LIGHT,
                 font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", **pad)
        self.enc_password = self._make_password_entry(parent)

        btn_row = tk.Frame(parent, bg=BG)
        btn_row.pack(fill="x", pady=(14, 4))
        RoundedButton(btn_row, text="Encrypt ➜", command=self.on_encrypt).pack(side="left")
        RoundedButton(btn_row, text="Load Sample", bg=PANEL_BG, hover="#3a3a52",
                      command=self.on_load_sample_encrypt).pack(side="left", padx=8)
        RoundedButton(btn_row, text="Clear", bg=PANEL_BG, hover="#3a3a52",
                      command=self.on_clear_encrypt).pack(side="left")

        tk.Label(parent, text="Encrypted output (Base64) — share this + your password to decrypt",
                 bg=BG, fg=TEXT_LIGHT, font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", **pad)
        self.enc_output = self._make_textbox(parent, height=6, readonly=True)

        RoundedButton(parent, text="Copy Output", bg=PANEL_BG, hover="#3a3a52",
                      command=lambda: self._copy_to_clipboard(self.enc_output)).pack(anchor="e", pady=(6, 0))

    # ---- Decrypt tab -----------------------------------------------------
    def _build_decrypt_tab(self, parent):
        pad = {"padx": 4, "pady": (12, 4)}

        tk.Label(parent, text="Encrypted message (Base64)", bg=BG, fg=TEXT_LIGHT,
                 font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", **pad)
        self.dec_input = self._make_textbox(parent, height=6)

        tk.Label(parent, text="Password / Key", bg=BG, fg=TEXT_LIGHT,
                 font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", **pad)
        self.dec_password = self._make_password_entry(parent)

        btn_row = tk.Frame(parent, bg=BG)
        btn_row.pack(fill="x", pady=(14, 4))
        RoundedButton(btn_row, text="Decrypt ➜", command=self.on_decrypt).pack(side="left")
        RoundedButton(btn_row, text="Use Last Encrypted Result", bg=PANEL_BG, hover="#3a3a52",
                      command=self.on_load_from_encrypt_output).pack(side="left", padx=8)
        RoundedButton(btn_row, text="Clear", bg=PANEL_BG, hover="#3a3a52",
                      command=self.on_clear_decrypt).pack(side="left")

        tk.Label(parent, text="Decrypted plaintext", bg=BG, fg=TEXT_LIGHT,
                 font=(FONT_FAMILY, 11, "bold")).pack(anchor="w", **pad)
        self.dec_output = self._make_textbox(parent, height=6, readonly=True)

        RoundedButton(parent, text="Copy Output", bg=PANEL_BG, hover="#3a3a52",
                      command=lambda: self._copy_to_clipboard(self.dec_output)).pack(anchor="e", pady=(6, 0))

    # ---- Status bar -----------------------------------------------------
    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready.")
        bar = tk.Frame(self, bg=PANEL_BG)
        bar.pack(fill="x", side="bottom")
        tk.Label(
            bar, textvariable=self.status_var, bg=PANEL_BG, fg=SUBTLE,
            font=(FONT_FAMILY, 9), anchor="w", padx=12, pady=6,
        ).pack(fill="x")

    # ------------------------------------------------------------------
    # Small UI helpers
    # ------------------------------------------------------------------
    def _make_textbox(self, parent, height=6, readonly=False):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground="#3f3f5a",
                          highlightthickness=1)
        frame.pack(fill="both", expand=False, pady=(0, 4))
        box = tk.Text(
            frame, height=height, wrap="word", bg=PANEL_BG, fg=TEXT_LIGHT,
            insertbackground=TEXT_LIGHT, relief="flat", padx=10, pady=8,
            font=(FONT_FAMILY, 10),
        )
        box.pack(fill="both", expand=True)
        if readonly:
            box.configure(state="disabled")
        return box

    def _make_password_entry(self, parent):
        frame = tk.Frame(parent, bg=PANEL_BG, highlightbackground="#3f3f5a",
                          highlightthickness=1)
        frame.pack(fill="x", pady=(0, 4))
        var_show = tk.BooleanVar(value=False)
        entry = tk.Entry(
            frame, show="•", bg=PANEL_BG, fg=TEXT_LIGHT, insertbackground=TEXT_LIGHT,
            relief="flat", font=(FONT_FAMILY, 11),
        )
        entry.pack(side="left", fill="x", expand=True, padx=10, pady=8)

        def toggle():
            entry.configure(show="" if var_show.get() else "•")
            var_show.set(not var_show.get())
            toggle_btn.configure(text="Hide" if var_show.get() else "Show")

        toggle_btn = tk.Button(
            frame, text="Show", command=toggle, bg=PANEL_BG, fg=SUBTLE,
            relief="flat", bd=0, font=(FONT_FAMILY, 9), cursor="hand2",
        )
        toggle_btn.pack(side="right", padx=8)
        return entry

    def _set_output(self, box, text):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    def _copy_to_clipboard(self, box):
        text = box.get("1.0", "end").strip()
        if not text:
            self._set_status("Nothing to copy yet.", ERROR)
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Copied to clipboard.", SUCCESS)

    def _set_status(self, message, color=SUBTLE):
        self.status_var.set(message)

    # ------------------------------------------------------------------
    # Button actions
    # ------------------------------------------------------------------
    def on_encrypt(self):
        plaintext = self.enc_input.get("1.0", "end-1c")
        password = self.enc_password.get()
        try:
            result = encrypt_text(plaintext, password)
            self._set_output(self.enc_output, result)
            self._set_status("Message encrypted successfully.", SUCCESS)
        except CryptoError as e:
            messagebox.showwarning("Cannot Encrypt", str(e))
            self._set_status(f"Encryption failed: {e}", ERROR)
        except Exception as e:  # noqa: BLE001 - final safety net for any unexpected error
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")
            self._set_status("Unexpected error during encryption.", ERROR)

    def on_decrypt(self):
        ciphertext = self.dec_input.get("1.0", "end-1c").strip()
        password = self.dec_password.get()
        try:
            result = decrypt_text(ciphertext, password)
            self._set_output(self.dec_output, result)
            self._set_status("Message decrypted successfully.", SUCCESS)
        except CryptoError as e:
            messagebox.showwarning("Cannot Decrypt", str(e))
            self._set_status(f"Decryption failed: {e}", ERROR)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Unexpected Error", f"Something went wrong:\n{e}")
            self._set_status("Unexpected error during decryption.", ERROR)

    def on_load_sample_encrypt(self):
        self.enc_input.delete("1.0", "end")
        self.enc_input.insert("1.0", SAMPLE_MESSAGE)
        self.enc_password.delete(0, "end")
        self.enc_password.insert(0, SAMPLE_PASSWORD)
        self._set_status("Sample message and password loaded. Click Encrypt to try it.")

    def on_clear_encrypt(self):
        self.enc_input.delete("1.0", "end")
        self.enc_password.delete(0, "end")
        self._set_output(self.enc_output, "")
        self._set_status("Encrypt tab cleared.")

    def on_clear_decrypt(self):
        self.dec_input.delete("1.0", "end")
        self.dec_password.delete(0, "end")
        self._set_output(self.dec_output, "")
        self._set_status("Decrypt tab cleared.")

    def on_load_from_encrypt_output(self):
        text = self.enc_output.get("1.0", "end-1c").strip()
        if not text:
            self._set_status("No encrypted result yet — encrypt a message first.", ERROR)
            messagebox.showinfo("Nothing to Load", "Encrypt a message on the Encrypt tab first.")
            return
        self.dec_input.delete("1.0", "end")
        self.dec_input.insert("1.0", text)
        pwd = self.enc_password.get()
        if pwd:
            self.dec_password.delete(0, "end")
            self.dec_password.insert(0, pwd)
        self._set_status("Loaded the last encrypted result into the Decrypt tab.")


if __name__ == "__main__":
    app = EncryptDecryptApp()
    app.mainloop()
