"""
Secure Password Manager (single-file)
- Uses SQLite to store credentials locally.
- Uses Fernet (from cryptography) with a key derived from a master password (PBKDF2HMAC + salt).
- Object-oriented design: Database, CryptoManager, PasswordGenerator, GUI App.

Features:
- Create vault (first run) with master password.
- Add, edit, delete credentials.
- Encrypt passwords before storing.
- Retrieve and decrypt passwords (view in GUI or copy).
- Password generator for strong random passwords.
- Export vault as an encrypted .txt backup.
- Input validation and error handling.

Requirements:
- Python 3.8+
- pip install cryptography

Run:
    python secure_password_manager.py

"""

import os
import sqlite3
import base64
import json
import secrets
import string
import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import getpass

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, InvalidToken
except Exception as e:
    raise SystemExit("cryptography package is required. Install with: pip install cryptography\n" + str(e))

# -------------------------
# Database layer
# -------------------------
class Database:
    """Handles SQLite operations and schema."""
    def __init__(self, path='vault.db'):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._setup()

    def _setup(self):
        c = self.conn.cursor()
        # settings table to store salt and verifier
        c.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB,
                verifier BLOB
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT,
                password BLOB NOT NULL,
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        # ensure single row in settings if absent
        c.execute('SELECT COUNT(*) FROM settings')
        if c.fetchone()[0] == 0:
            c.execute('INSERT INTO settings (id) VALUES (1)')
            self.conn.commit()

    def get_settings(self):
        c = self.conn.cursor()
        c.execute('SELECT salt, verifier FROM settings WHERE id = 1')
        return c.fetchone()

    def set_settings(self, salt: bytes, verifier: bytes):
        c = self.conn.cursor()
        c.execute('UPDATE settings SET salt = ?, verifier = ? WHERE id = 1', (salt, verifier))
        self.conn.commit()

    def add_credential(self, site, username, password_blob, notes=''):
        now = datetime.datetime.utcnow().isoformat()
        c = self.conn.cursor()
        c.execute('''INSERT INTO credentials (site, username, password, notes, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?)''', (site, username, password_blob, notes, now, now))
        self.conn.commit()
        return c.lastrowid

    def update_credential(self, cred_id, site, username, password_blob, notes=''):
        now = datetime.datetime.utcnow().isoformat()
        c = self.conn.cursor()
        c.execute('''UPDATE credentials SET site=?, username=?, password=?, notes=?, updated_at=? WHERE id=?''',
                  (site, username, password_blob, notes, now, cred_id))
        self.conn.commit()

    def delete_credential(self, cred_id):
        c = self.conn.cursor()
        c.execute('DELETE FROM credentials WHERE id=?', (cred_id,))
        self.conn.commit()

    def list_credentials(self, search=None):
        c = self.conn.cursor()
        if search:
            like = f'%{search}%'
            c.execute('SELECT id, site, username, created_at, updated_at FROM credentials WHERE site LIKE ? OR username LIKE ? ORDER BY site', (like, like))
        else:
            c.execute('SELECT id, site, username, created_at, updated_at FROM credentials ORDER BY site')
        return c.fetchall()

    def get_credential(self, cred_id):
        c = self.conn.cursor()
        c.execute('SELECT * FROM credentials WHERE id=?', (cred_id,))
        return c.fetchone()

# -------------------------
# Crypto layer
# -------------------------
class CryptoManager:
    """Derives a Fernet key from a master password and handles encryption/decryption."""
    def __init__(self, db: Database, iterations=390000):
        self.db = db
        self.iterations = iterations
        self.backend = default_backend()
        self.fernet = None
        self.master_key = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        # PBKDF2HMAC to derive 32-byte key, then urlsafe_b64encode for Fernet
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=self.backend
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key

    def setup_master_password(self, master_password: str):
        """Initialize vault: create salt and verifier stored in DB."""
        # create salt
        salt = secrets.token_bytes(16)
        key = self._derive_key(master_password, salt)
        # verifier: encrypt a known token to verify future passwords
        f = Fernet(key)
        token = b'vault_verification_token'
        verifier = f.encrypt(token)
        self.db.set_settings(salt, verifier)
        # store fernet for session
        self.fernet = f
        self.master_key = key

    def unlock(self, master_password: str) -> bool:
        s = self.db.get_settings()
        salt = s['salt']
        verifier = s['verifier']
        if not salt or not verifier:
            raise RuntimeError('Vault not initialized. Set up master password first.')
        key = self._derive_key(master_password, salt)
        f = Fernet(key)
        try:
            token = f.decrypt(verifier)
            if token == b'vault_verification_token':
                self.fernet = f
                self.master_key = key
                return True
            return False
        except InvalidToken:
            return False

    def encrypt(self, plaintext: str) -> bytes:
        if not self.fernet:
            raise RuntimeError('Vault locked')
        return self.fernet.encrypt(plaintext.encode('utf-8'))

    def decrypt(self, ciphertext: bytes) -> str:
        if not self.fernet:
            raise RuntimeError('Vault locked')
        try:
            return self.fernet.decrypt(ciphertext).decode('utf-8')
        except InvalidToken:
            raise ValueError('Decryption failed — invalid token or key')

    def export_backup(self, filepath):
        """Export entire vault as decrypted JSON, then encrypt it (so backup file is safe).
        The backup is encrypted with the same session key.
        """
        c = self.db.conn.cursor()
        c.execute('SELECT id, site, username, password, notes, created_at, updated_at FROM credentials')
        rows = c.fetchall()
        data = []
        for r in rows:
            try:
                pwd = self.decrypt(r['password'])
            except Exception:
                pwd = '<decryption_error>'
            data.append({
                'id': r['id'],
                'site': r['site'],
                'username': r['username'],
                'password': pwd,
                'notes': r['notes'],
                'created_at': r['created_at'],
                'updated_at': r['updated_at']
            })
        json_blob = json.dumps({'exported_at': datetime.datetime.utcnow().isoformat(), 'entries': data}, indent=2)
        encrypted = self.fernet.encrypt(json_blob.encode('utf-8'))
        with open(filepath, 'wb') as fh:
            fh.write(encrypted)

# -------------------------
# Password generator
# -------------------------
class PasswordGenerator:
    @staticmethod
    def generate(length=16, use_symbols=True, use_numbers=True, use_upper=True, use_lower=True):
        if length < 6:
            raise ValueError('Password length must be at least 6')
        pool = ''
        if use_lower:
            pool += string.ascii_lowercase
        if use_upper:
            pool += string.ascii_uppercase
        if use_numbers:
            pool += string.digits
        if use_symbols:
            pool += '!@#$%^&*()-_=+[]{};:,.<>?'
        if not pool:
            raise ValueError('No character sets selected')
        # ensure at least one char from each selected set
        password = []
        if use_lower:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_upper:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_numbers:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice('!@#$%^&*()-_=+[]{};:,.<>?'))
        while len(password) < length:
            password.append(secrets.choice(pool))
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

# -------------------------
# GUI Application
# -------------------------
class PasswordManagerApp(tk.Tk):
    def __init__(self, db_path='vault.db'):
        super().__init__()
        self.title('Secure Password Manager')
        self.geometry('800x480')
        self.db = Database(db_path)
        self.crypto = CryptoManager(self.db)
        self._build_ui()
        # at start: prompt for master password or setup
        self._startup_unlock()

    def _startup_unlock(self):
        settings = self.db.get_settings()
        salt, verifier = settings['salt'], settings['verifier']
        if not salt or not verifier:
            # first run: ask to create master password
            while True:
                pw1 = simpledialog.askstring('Setup', 'Create a master password (will unlock your vault):', show='*')
                if pw1 is None:
                    self.quit(); return
                if len(pw1) < 8:
                    messagebox.showwarning('Weak password', 'Master password should be at least 8 characters.')
                    continue
                pw2 = simpledialog.askstring('Confirm', 'Confirm master password:', show='*')
                if pw1 != pw2:
                    messagebox.showerror('Mismatch', 'Passwords did not match. Try again.')
                    continue
                self.crypto.setup_master_password(pw1)
                messagebox.showinfo('Vault Created', 'Master password saved. Remember it — there is no recovery.')
                break
        else:
            # prompt to unlock
            for _ in range(3):
                pw = simpledialog.askstring('Unlock Vault', 'Enter master password:', show='*')
                if pw is None:
                    self.quit(); return
                ok = self.crypto.unlock(pw)
                if ok:
                    break
                else:
                    messagebox.showerror('Wrong password', 'Master password incorrect.')
            else:
                messagebox.showerror('Locked out', 'Failed to unlock vault. Exiting.')
                self.quit(); return
        # if unlocked, refresh list
        self.refresh_list()

    def _build_ui(self):
        # top toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(side='top', fill='x')

        add_btn = ttk.Button(toolbar, text='Add', command=self.add_dialog)
        add_btn.pack(side='left', padx=4, pady=4)
        edit_btn = ttk.Button(toolbar, text='Edit', command=self.edit_selected)
        edit_btn.pack(side='left', padx=4, pady=4)
        del_btn = ttk.Button(toolbar, text='Delete', command=self.delete_selected)
        del_btn.pack(side='left', padx=4, pady=4)

        gen_btn = ttk.Button(toolbar, text='Generate', command=self.generate_password_dialog)
        gen_btn.pack(side='left', padx=4, pady=4)

        exp_btn = ttk.Button(toolbar, text='Export backup', command=self.export_backup)
        exp_btn.pack(side='left', padx=4, pady=4)

        search_lbl = ttk.Label(toolbar, text='Search:')
        search_lbl.pack(side='left', padx=(20,4))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var)
        search_entry.pack(side='left', padx=4)
        search_entry.bind('<Return>', lambda e: self.refresh_list())
        search_btn = ttk.Button(toolbar, text='Go', command=self.refresh_list)
        search_btn.pack(side='left', padx=4)

        # main panes
        main = ttk.Panedwindow(self, orient='horizontal')
        main.pack(fill='both', expand=True)

        left = ttk.Frame(main, width=300)
        right = ttk.Frame(main)
        main.add(left, weight=1)
        main.add(right, weight=3)

        # listbox
        self.cred_list = ttk.Treeview(left, columns=('site','username','created','updated'), show='headings')
        self.cred_list.heading('site', text='Site')
        self.cred_list.heading('username', text='Username')
        self.cred_list.heading('created', text='Created')
        self.cred_list.heading('updated', text='Updated')
        self.cred_list.pack(fill='both', expand=True)
        self.cred_list.bind('<<TreeviewSelect>>', lambda e: self.show_selected())

        # detail area
        self.detail_text = tk.Text(right, state='disabled', wrap='word')
        self.detail_text.pack(fill='both', expand=True, padx=6, pady=6)

    def refresh_list(self):
        for i in self.cred_list.get_children():
            self.cred_list.delete(i)
        search = self.search_var.get().strip()
        rows = self.db.list_credentials(search=search if search else None)
        for r in rows:
            self.cred_list.insert('', 'end', iid=str(r['id']), values=(r['site'], r['username'] or '', r['created_at'] or '', r['updated_at'] or ''))

    def show_selected(self):
        sel = self.cred_list.selection()
        if not sel:
            return
        cred_id = int(sel[0])
        r = self.db.get_credential(cred_id)
        # decrypt password
        try:
            pwd = self.crypto.decrypt(r['password'])
        except Exception as e:
            pwd = f'<error: {e}>'
        content = f"Site: {r['site']}\nUsername: {r['username']}\nPassword: {pwd}\nNotes: {r['notes']}\nCreated at: {r['created_at']}\nUpdated at: {r['updated_at']}"
        self.detail_text.configure(state='normal')
        self.detail_text.delete('1.0', 'end')
        self.detail_text.insert('1.0', content)
        self.detail_text.configure(state='disabled')

    def add_dialog(self):
        d = CredentialDialog(self, title='Add credential')
        self.wait_window(d)
        if d.result:
            site, username, password, notes = d.result
            # validate
            if not site or not password:
                messagebox.showerror('Invalid input', 'Site and password are required.')
                return
            enc = self.crypto.encrypt(password)
            self.db.add_credential(site.strip(), username.strip() if username else '', enc, notes.strip() if notes else '')
            self.refresh_list()

    def edit_selected(self):
        sel = self.cred_list.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select an entry to edit')
            return
        cred_id = int(sel[0])
        r = self.db.get_credential(cred_id)
        try:
            pwd = self.crypto.decrypt(r['password'])
        except Exception as e:
            messagebox.showerror('Decryption error', f'Could not decrypt password: {e}')
            return
        d = CredentialDialog(self, title='Edit credential', site=r['site'], username=r['username'], password=pwd, notes=r['notes'])
        self.wait_window(d)
        if d.result:
            site, username, password, notes = d.result
            if not site or not password:
                messagebox.showerror('Invalid input', 'Site and password are required.')
                return
            enc = self.crypto.encrypt(password)
            self.db.update_credential(cred_id, site.strip(), username.strip() if username else '', enc, notes.strip() if notes else '')
            self.refresh_list()

    def delete_selected(self):
        sel = self.cred_list.selection()
        if not sel:
            messagebox.showinfo('Select', 'Select an entry to delete')
            return
        cred_id = int(sel[0])
        if messagebox.askyesno('Confirm', 'Delete selected credential?'):
            self.db.delete_credential(cred_id)
            self.refresh_list()
            self.detail_text.configure(state='normal')
            self.detail_text.delete('1.0', 'end')
            self.detail_text.configure(state='disabled')

    def generate_password_dialog(self):
        length = simpledialog.askinteger('Password length', 'Length (min 6):', minvalue=6, initialvalue=16)
        if length is None:
            return
        pwd = PasswordGenerator.generate(length=length)
        # show and allow user to copy
        messagebox.showinfo('Generated password', f'Password:\n{pwd}')

    def export_backup(self):
        f = filedialog.asksaveasfilename(title='Export encrypted backup', defaultextension='.backup', filetypes=[('Backup','*.backup'),('All','*.*')])
        if not f:
            return
        try:
            self.crypto.export_backup(f)
            messagebox.showinfo('Exported', f'Backup written to {f}')
        except Exception as e:
            messagebox.showerror('Export failed', str(e))

# -------------------------
# Credential dialog (add/edit)
# -------------------------
class CredentialDialog(tk.Toplevel):
    def __init__(self, parent, title='Credential', site='', username='', password='', notes=''):
        super().__init__(parent)
        self.transient(parent)
        self.title(title)
        self.result = None
        self._build(site, username, password, notes)
        self.grab_set()
        self.protocol('WM_DELETE_WINDOW', self._on_cancel)

    def _build(self, site, username, password, notes):
        frm = ttk.Frame(self)
        frm.pack(padx=10, pady=10, fill='both', expand=True)

        ttk.Label(frm, text='Site:').grid(row=0, column=0, sticky='w')
        self.site_var = tk.StringVar(value=site)
        ttk.Entry(frm, textvariable=self.site_var, width=50).grid(row=0, column=1, sticky='we')

        ttk.Label(frm, text='Username:').grid(row=1, column=0, sticky='w')
        self.user_var = tk.StringVar(value=username)
        ttk.Entry(frm, textvariable=self.user_var, width=50).grid(row=1, column=1, sticky='we')

        ttk.Label(frm, text='Password:').grid(row=2, column=0, sticky='w')
        self.pw_var = tk.StringVar(value=password)
        ttk.Entry(frm, textvariable=self.pw_var, width=50, show='*').grid(row=2, column=1, sticky='we')
        show_btn = ttk.Button(frm, text='Show', command=self._toggle_pw)
        show_btn.grid(row=2, column=2, padx=6)

        ttk.Label(frm, text='Notes:').grid(row=3, column=0, sticky='nw')
        self.notes_txt = tk.Text(frm, width=50, height=6)
        self.notes_txt.grid(row=3, column=1, sticky='we')
        self.notes_txt.insert('1.0', notes)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=4, column=0, columnspan=3, pady=(10,0))
        ok = ttk.Button(btn_frm, text='OK', command=self._on_ok)
        ok.pack(side='left', padx=4)
        cancel = ttk.Button(btn_frm, text='Cancel', command=self._on_cancel)
        cancel.pack(side='left', padx=4)

    def _toggle_pw(self):
        # show/hide password
        ent = self.children['!frame'].children
        # simpler: find entry by variable
        for w in self.winfo_children():
            pass
        # toggle based on current show char
        entries = [w for w in self.children['!frame'].winfo_children() if isinstance(w, ttk.Entry)]
        for e in entries:
            if str(e['textvariable']) == str(self.pw_var):
                if e['show'] == '*':
                    e.config(show='')
                else:
                    e.config(show='*')
                break

    def _on_ok(self):
        site = self.site_var.get().strip()
        username = self.user_var.get().strip()
        password = self.pw_var.get()
        notes = self.notes_txt.get('1.0', 'end').strip()
        if not site or not password:
            messagebox.showerror('Invalid', 'Site and password are required')
            return
        self.result = (site, username, password, notes)
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()

# -------------------------
# Run
# -------------------------
if __name__ == '__main__':
    app = PasswordManagerApp()
    app.mainloop()
