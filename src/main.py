import os
import sys
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, PhotoImage
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import logging
from datetime import datetime, timedelta, timezone
import random
import string

# Optional PyInstaller fix
if hasattr(sys, '_MEIPASS'):
    os.environ['TCL_LIBRARY'] = os.path.join(sys._MEIPASS, 'tcl', 'tcl8.6')
    os.environ['TK_LIBRARY'] = os.path.join(sys._MEIPASS, 'tcl', 'tk8.6')

SALT_FILE = "salt.salt"
KEY_FILE = "master.key"
DB_FILE = "passwords.txt"
ITERATIONS = 300000
SALT_LENGTH = 32
LOG_FILE = "activity.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def log_event(event):
    logging.info(event)

def generate_salt():
    if not os.path.exists(SALT_FILE):
        with open(SALT_FILE, "wb") as f:
            f.write(os.urandom(SALT_LENGTH))
        log_event("New salt generated.")

def load_salt():
    with open(SALT_FILE, "rb") as f:
        return f.read()

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def set_master_password(password):
    key = derive_key(password, salt)
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    log_event("Master password set.")

def verify_master_password(password):
    if not os.path.exists(KEY_FILE):
        return False
    key = derive_key(password, salt)
    with open(KEY_FILE, "rb") as f:
        return f.read() == key

def encrypt(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt(token):
    return fernet.decrypt(token.encode()).decode()

def read_db():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r") as f:
        return [line.strip().split("|") for line in f if line.count("|") == 2]

def write_db(entries):
    with open(DB_FILE, "w") as f:
        for entry in entries:
            f.write("|".join(entry) + "\n")

def refresh_dropdown():
    items = [entry[0] for entry in read_db()]
    dropdown['values'] = items
    dropdown.set("")
    if 'result_label' in globals():
        result_label.config(text="")
        copy_frame.pack_forget()

def add_password():
    label, user, pwd = label_entry.get().strip(), user_entry.get().strip(), pass_entry.get().strip()
    if not label or not user or not pwd:
        messagebox.showerror("Missing Info", "Please fill all fields.")
        return
    with open(DB_FILE, "a") as f:
        f.write(f"{label}|{user}|{encrypt(pwd)}\n")
    label_entry.delete(0, tk.END)
    user_entry.delete(0, tk.END)
    pass_entry.delete(0, tk.END)
    refresh_dropdown()
    log_event(f"Password added for '{label}'")
    messagebox.showinfo("Saved", f"\u2705 '{label}' stored.")

def view_password():
    label = dropdown.get()
    for l, u, p in read_db():
        if l == label:
            try: pw = decrypt(p)
            except: pw = "[Corrupt]"
            result_label.config(text=f"\U0001F464 {u}\n\U0001F511 {pw}")
            log_event(f"Password viewed for '{label}'")
            copy_user_btn.config(command=lambda: copy_to_clipboard(u, "Username"))
            copy_pass_btn.config(command=lambda: copy_to_clipboard(pw, "Password"))
            copy_frame.pack(pady=2)
            return

def copy_to_clipboard(value, label):
    root.clipboard_clear()
    root.clipboard_append(value)
    messagebox.showinfo("Copied", f"{label} copied to clipboard.")

def edit_password():
    label = dropdown.get()
    entries = read_db()
    for i, (l, u, p) in enumerate(entries):
        if l == label:
            new_u = simpledialog.askstring("Edit Username", "Leave blank to keep current", initialvalue=u)
            new_p = simpledialog.askstring("Edit Password", "Leave blank to keep current")
            if new_u and new_u.strip(): u = new_u.strip()
            if new_p and new_p.strip(): p = encrypt(new_p.strip())
            entries[i] = [l, u, p]
            write_db(entries)
            refresh_dropdown()
            log_event(f"Password edited for '{label}'")
            messagebox.showinfo("Updated", f"\u270F\ufe0f '{label}' updated.")
            return

def delete_password():
    label = dropdown.get()
    if messagebox.askyesno("Delete", f"Delete '{label}'?"):
        write_db([e for e in read_db() if e[0] != label])
        refresh_dropdown()
        log_event(f"Password deleted for '{label}'")
        messagebox.showinfo("Deleted", f"\U0001F5D1\ufe0f '{label}' removed.")

def change_master():
    new = simpledialog.askstring("New Password", "Enter new master password:", show="*")
    confirm = simpledialog.askstring("Confirm", "Re-enter password:", show="*")
    if new and new == confirm:
        set_master_password(new)
        log_event("Master password changed.")
        messagebox.showinfo("Updated", "\U0001F510 Master password changed.")
    else:
        messagebox.showerror("Error", "Mismatch or blank.")

def update_time():
    est_now = datetime.now().astimezone(timezone(timedelta(hours=-4)))
    now_str = est_now.strftime('%Y-%m-%d %H:%M:%S EST')
    time_label.config(text=now_str)
    root.after(1000, update_time)

# ---------- INIT ----------
generate_salt()
salt = load_salt()

root = tk.Tk()
root.withdraw()

if not os.path.exists(KEY_FILE):
    pw = simpledialog.askstring("Set Master Password", "Create one:", show="*")
    confirm = simpledialog.askstring("Confirm", "Re-enter:", show="*")
    if not pw or pw != confirm:
        messagebox.showerror("Setup Failed", "Password mismatch or blank.")
        exit()
    set_master_password(pw)
    key = derive_key(pw, salt)
    fernet = Fernet(key)
else:
    pw = simpledialog.askstring("Master Password", "Enter password:", show="*")
    key = derive_key(pw, salt)
    fernet = Fernet(key)
    if not verify_master_password(pw):
        messagebox.showerror("Access Denied", "Incorrect password.")
        exit()

# [Previous imports, constants, and function definitions remain unchanged]
# ↓ Scroll to GUI section for visual improvements ↓

root.deiconify()
root.title("\U0001F510 Encrypted Password Manager")
root.geometry("700x800")
root.resizable(False, False)
root.configure(bg="#1a1a1a")

# Sidebar and Frames
def show_frame(frame):
    manager_frame.pack_forget()
    generator_frame.pack_forget()
    frame.pack(side="right", fill="both", expand=True)

sidebar = tk.Frame(root, width=130, bg="#121212")
sidebar.pack(side="left", fill="y")

font_text = ("Segoe UI", 10)
font_head = ("Segoe UI", 14, "bold")

tk.Label(sidebar, text="\U0001F510", bg="#121212", fg="white", font=("Segoe UI", 20)).pack(pady=(30, 20))
tk.Button(sidebar, text="🔐 Manager", font=font_text, bg="#2b2b2b", fg="white", relief="flat", command=lambda: show_frame(manager_frame)).pack(pady=10, ipadx=50, ipady=50, fill="x")
tk.Button(sidebar, text="🎲 Generator", font=font_text, bg="#2b2b2b", fg="white", relief="flat", command=lambda: show_frame(generator_frame)).pack(pady=10, ipadx=50, ipady=50, fill="x")
tk.Button(sidebar, text="🔁 Change Master Password", command=change_master, font=font_text, bg="#2b2b2b", fg="white", relief="flat", activebackground="#444", padx=10, pady=10).pack(side="bottom", fill="x", pady=20)


# Styles
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=font_text, background="#2b2b2b", foreground="white", borderwidth=0)
style.map("TButton", background=[("active", "#444")], relief=[("pressed", "flat"), ("!pressed", "flat")])
style.configure("TCombobox", font=font_text, fieldbackground="#2b2b2b", background="#2b2b2b", foreground="white")

# -------- MANAGER FRAME --------
manager_frame = tk.Frame(root, bg="#1a1a1a")
manager_frame.pack(side="right", fill="both", expand=True)

def field(label, show=None):
    frame = tk.Frame(manager_frame, bg="#1a1a1a")
    tk.Label(frame, text=label, bg="#1a1a1a", fg="#cccccc", font=font_text).pack(anchor="w")
    e = tk.Entry(frame, font=font_text, width=40, show=show, bg="#2b2b2b", fg="white", insertbackground="white", relief="flat")
    e.pack(pady=(0, 8))
    frame.pack(pady=(6, 0))
    return e

time_label = tk.Label(manager_frame, text="", font=("Segoe UI", 9), fg="#bbbbbb", bg="#1a1a1a")
time_label.pack(anchor="e", padx=10)
update_time()

welcome = tk.Label(manager_frame, text="\U0001F324\ufe0f Welcome, User!", font=("Segoe UI", 16, "bold"), fg="white", bg="#1a1a1a")
welcome.pack(pady=(10, 5))

tk.Label(manager_frame, text="➕ Add New Credential", font=font_head, bg="#1a1a1a", fg="#00ffcc").pack(pady=(12, 10))
label_entry = field("Label (e.g. Gmail, Netflix):")
user_entry = field("Username:")
pass_entry = field("Password:", show="*")
ttk.Button(manager_frame, text="💾 Save Entry", command=add_password).pack(pady=18)

tk.Label(manager_frame, text="📂 Manage Saved Entries", font=font_head, bg="#1a1a1a", fg="#00ccff").pack(pady=(25, 10))
dropdown = ttk.Combobox(manager_frame, state="readonly", font=font_text)
dropdown.pack(pady=(0, 10))
refresh_dropdown()

button_frame = tk.Frame(manager_frame, bg="#1a1a1a")
button_frame.pack()
for text, cmd in [
    ("👁️ View", view_password),
    ("✏️ Edit", edit_password),
    ("🗑️ Delete", delete_password)
]:
    tk.Button(button_frame, text=text, command=cmd, font=font_text, bg="#2b2b2b", fg="white", relief="flat", activebackground="#444", padx=10, pady=4).pack(side="left", padx=8)

result_label = tk.Label(manager_frame, text="", font=font_text, bg="#1a1a1a", fg="#dddddd", justify="left", wraplength=580)
result_label.pack(pady=12)

copy_frame = tk.Frame(manager_frame, bg="#1a1a1a")
copy_user_btn = tk.Button(copy_frame, text="📋 Copy Username", command=lambda: None, font=font_text, bg="#2b2b2b", fg="white", relief="flat", activebackground="#444", padx=20)
copy_user_btn.grid(row=0, column=0, padx=5)
copy_pass_btn = tk.Button(copy_frame, text="📋 Copy Password", command=lambda: None, font=font_text, bg="#2b2b2b", fg="white", relief="flat", activebackground="#444", padx=20)
copy_pass_btn.grid(row=0, column=1, padx=5)
copy_frame.pack_forget()  # Hide on app launch

# -------- GENERATOR FRAME --------
generator_frame = tk.Frame(root, bg="#1a1a1a")

tk.Label(generator_frame, text="🔐 Password Generator", font=("Segoe UI", 16, "bold"), bg="#1a1a1a", fg="#00ffff").pack(pady=(30, 10))

length_slider = tk.Scale(
    generator_frame, from_=8, to=32, orient="horizontal",
    label="Password Length", length=450,
    bg="#1a1a1a", fg="white", troughcolor="#444",
    highlightthickness=0, font=("Segoe UI", 10)
)
length_slider.set(40)
length_slider.pack(pady=(0, 20))

include_lowercase_var = tk.BooleanVar(value=True)
include_uppercase_var = tk.BooleanVar(value=True)
include_numbers_var = tk.BooleanVar(value=True)
include_symbols_var = tk.BooleanVar(value=True)

options_frame = tk.Frame(generator_frame, bg="#1a1a1a")
for text, var in [
    ("a-z", include_lowercase_var),
    ("A-Z", include_uppercase_var),
    ("0-9", include_numbers_var),
    ("!@#", include_symbols_var)
]:
    tk.Checkbutton(
        options_frame, text=text, variable=var,
        bg="#1a1a1a", fg="#cccccc", font=font_text,
        selectcolor="#1a1a1a", activebackground="#1a1a1a"
    ).pack(side="left", padx=10)
options_frame.pack(pady=(0, 15))

strength_label = tk.Label(generator_frame, text="Strength: ", font=("Segoe UI", 10, "bold"), bg="#1a1a1a", fg="#ffcc00")
strength_label.pack()

#crack time
crack_label = tk.Label(generator_frame, text="", font=("Segoe UI", 10, "italic"), bg="#1a1a1a", fg="#bbbbbb")
crack_label.pack(pady=(0, 10))
#---

generated_entry = tk.Entry(generator_frame, font=("Segoe UI", 13), width=48, justify="center", bg="#262626", fg="#00ffcc", relief="flat")
generated_entry.pack(pady=12)

generated_history = []

def update_history_box():
    history_box.config(state="normal")
    history_box.delete(1.0, tk.END)
    for pw in reversed(generated_history[-5:]):
        history_box.insert(tk.END, pw + "\n")
    history_box.config(state="disabled")

def generate_password():
    length = length_slider.get()
    charset = ""
    if include_lowercase_var.get(): charset += string.ascii_lowercase
    if include_uppercase_var.get(): charset += string.ascii_uppercase
    if include_numbers_var.get(): charset += string.digits
    if include_symbols_var.get(): charset += "!@#$%^&*()-_=+[]{}|;:,.<>/?"

    if not charset:
        generated_entry.delete(0, tk.END)
        generated_entry.insert(0, "Select at least one option.")
        return

    password = ''.join(random.choice(charset) for _ in range(length))
    generated_entry.delete(0, tk.END)
    generated_entry.insert(0, password)

    assess_strength(password, charset)
    generated_history.append(password)
    update_history_box()
    estimate_crack_time(password)

    password = ''.join(random.choice(charset) for _ in range(length))
    generated_entry.delete(0, tk.END)
    generated_entry.insert(0, password)
    assess_strength(password, charset)

def estimate_crack_time(pw):
    charset_size = 0
    if any(c.islower() for c in pw): charset_size += 26
    if any(c.isupper() for c in pw): charset_size += 26
    if any(c.isdigit() for c in pw): charset_size += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>/?" for c in pw): charset_size += 32

    guesses = charset_size ** len(pw)
    guesses_per_second = 1_000_000_000  # 1 billion guesses/sec
    seconds = guesses / guesses_per_second

    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        return f"{seconds/31536000:.2f} years"


def copy_generated_password():
    password = generated_entry.get()
    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Generated password copied to clipboard.")

def assess_strength(pw, charset):
    score = 0
    if any(c.islower() for c in pw): score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>/?" for c in pw): score += 1
    if len(pw) >= 16: score += 1

    levels = {1: "Very Weak", 2: "Weak", 3: "Medium", 4: "Strong", 5: "Very Strong"}
    colors = {1: "#ff5555", 2: "#ff8844", 3: "#ffcc00", 4: "#99ff33", 5: "#33ff88"}
    strength_label.config(text=f"Strength: {levels[score]}", fg=colors[score])
    crack_label.config(text=f"Est. Crack Time: {estimate_crack_time(pw)}")


btn_frame = tk.Frame(generator_frame, bg="#1a1a1a")
tk.Button(btn_frame, text="🎲 Generate", command=generate_password, font=font_text,
          bg="#00cc99", fg="black", relief="flat", padx=20, pady=5, activebackground="#00b38f").pack(side="left", padx=10)
tk.Button(btn_frame, text="📋 Copy", command=copy_generated_password, font=font_text,
          bg="#3399ff", fg="black", relief="flat", padx=20, pady=5, activebackground="#2d88d6").pack(side="left", padx=10)
btn_frame.pack(pady=15)

tips_frame = tk.LabelFrame(generator_frame, text="🔎 Password Tips", font=("Segoe UI", 10, "bold"),
                           bg="#1a1a1a", fg="#00ffff", bd=1, relief="groove", labelanchor="n")
tips_frame.pack(padx=20, pady=20, fill="x")

tk.Label(tips_frame, text="• Use 16+ characters whenever possible.\n"
                          "• Include symbols and numbers for strength.\n"
                          "• Avoid using the same password across accounts.\n"
                          "• Use a password manager to store and organize.",
         justify="left", font=("Segoe UI", 9), bg="#1a1a1a", fg="#bbbbbb").pack(padx=10, pady=10, anchor="w")


tk.Label(generator_frame, text="Recent Passwords", font=("Segoe UI", 10, "bold"),
         bg="#1a1a1a", fg="#888888").pack()
history_box = tk.Text(generator_frame, height=5, width=50, bg="#121212", fg="#00ffcc",
                      font=("Courier New", 9), relief="flat", state="disabled")
history_box.pack(pady=(0, 20))


root.mainloop()
