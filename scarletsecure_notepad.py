import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, font
import threading                 # For running file and search operations in threads to avoid UI blocking
import os
import re
import queue                    # Thread-safe queue for scheduling Tkinter UI updates in main thread
import json                     # For JSON serialization of encrypted file data

from Crypto.Cipher import AES   # AES cipher for encryption/decryption
from Crypto.Random import get_random_bytes  # To generate secure random salt and nonce
from Crypto.Protocol.KDF import PBKDF2       # Password-based key derivation function for secure keys

# === Constants defining the color scheme for the editor ===
COLOR_BLACK = "#000000"                      # Background color: pure black for eye protection
COLOR_SCARLET = "#FF2400"                    # Default text color: scarlet red (important for eye fatigue)
COLOR_GOLDEN = "#FFD700"                     # Selection and highlight text color: golden
COLOR_GREEN_BG = "#008000"                   # Selection and highlight background color: green
COLOR_HIGHLIGHT_FG = COLOR_GOLDEN            # Highlight foreground color alias
COLOR_HIGHLIGHT_BG = COLOR_GREEN_BG          # Highlight background color alias

# === Crypto parameters for good security ===
PBKDF2_ITERATIONS = 1000                     # Number of iterations in key derivation, balance security & performance
SALT_SIZE = 16                               # Length of salt in bytes for key derivation

# === Global variables used throughout the program ===
tabs = []                                    # List of dictionaries representing each open tab and its widgets/state
root = None                                  # Root Tk window
notebook = None                              # ttk.Notebook widget containing tabs
ui_queue = queue.Queue()                      # Thread-safe queue to stage UI updates on main thread

# === Key derivation with PBKDF2, returns 256-bit key ===
def derive_key(password, salt):
    return PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITERATIONS)

# === Encrypt arbitrary string text using password, and package result as JSON bytes ===
def encrypt_text(text, password):
    salt = get_random_bytes(SALT_SIZE)                       # Random salt for key derivation per file
    key = derive_key(password, salt)                         # Derive symmetric key from password+salt
    cipher = AES.new(key, AES.MODE_GCM)                      # AES in GCM mode for authenticated encryption
    nonce = cipher.nonce                                      # Get cipher-generated unique nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))   # Encrypt with authentication tag
    # Package pieces into hex strings into a dict, then JSON-encode as bytes to store in file
    data_dict = {
        'salt': salt.hex(),
        'nonce': nonce.hex(),
        'tag': tag.hex(),
        'ciphertext': ciphertext.hex(),
    }
    return json.dumps(data_dict).encode('utf-8')

# === Decrypt json-serialized bytes with password, returning the plaintext string ===
def decrypt_text(data, password):
    data_dict = json.loads(data.decode('utf-8'))              # Parse JSON into dict
    salt = bytes.fromhex(data_dict['salt'])                    # Extract salt bytes
    nonce = bytes.fromhex(data_dict['nonce'])                  # Extract nonce bytes
    tag = bytes.fromhex(data_dict['tag'])                      # Extract tag bytes
    ciphertext = bytes.fromhex(data_dict['ciphertext'])        # Extract ciphertext bytes
    key = derive_key(password, salt)                            # Derive key again with password + salt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)           # Initialize cipher with nonce
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)     # Decrypt and verify authenticity
    return decrypted.decode('utf-8')                            # Decode UTF-8 plaintext

# === Setup main window and Qt Notebook tabs ===
def create_main_window():
    global root, notebook
    root = tk.Tk()
    root.title("Scarlet on Black Notepad (AES Encrypted)")     # Window title showing encryption feature
    root.geometry("900x650")                                    # Default window size

    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)                     # Fill entire window

    create_menu()                                               # Setup menubar and menus
    add_tab("Introduction", intro=True)                         # Add initial tab with instructions shown

    root.bind_all("<Control-Tab>", next_tab)                    # Ctrl+Tab: next tab
    root.bind_all("<Control-Shift-Tab>", prev_tab)              # Ctrl+Shift+Tab: previous tab

    root.after(100, process_ui_queue)                           # Schedule periodic processing of UI updates from threads

# === Build menu bar with File, Edit, and View functionality ===
def create_menu():
    menu_bar = tk.Menu(root)

    # File menu: new/open/save/saveas/close tab/exit
    file_menu = tk.Menu(menu_bar, tearoff=0)
    file_menu.add_command(label="New Tab", command=add_tab, accelerator="Ctrl+N")
    file_menu.add_command(label="Open", command=lambda: run_thread(open_file), accelerator="Ctrl+O")
    file_menu.add_command(label="Save", command=lambda: run_thread(save_file), accelerator="Ctrl+S")
    file_menu.add_command(label="Save As", command=lambda: run_thread(save_as_file))
    file_menu.add_separator()
    file_menu.add_command(label="Close Tab", command=close_current_tab, accelerator="Ctrl+W")
    file_menu.add_command(label="Exit", command=root.quit)
    menu_bar.add_cascade(label="File", menu=file_menu)

    # Edit menu: Find/Find & Replace, Undo/Redo
    edit_menu = tk.Menu(menu_bar, tearoff=0)
    edit_menu.add_command(label="Find", command=open_find_dialog, accelerator="Ctrl+F")
    edit_menu.add_command(label="Find & Replace", command=open_find_replace_dialog, accelerator="Ctrl+H")
    edit_menu.add_separator()
    edit_menu.add_command(label="Undo", command=undo_edit, accelerator="Ctrl+Z")
    edit_menu.add_command(label="Redo", command=redo_edit, accelerator="Ctrl+Y")
    menu_bar.add_cascade(label="Edit", menu=edit_menu)

    # View menu: set absolute font size via prompt
    view_menu = tk.Menu(menu_bar, tearoff=0)
    view_menu.add_command(label="Set Font Size", command=set_font_size_prompt)
    menu_bar.add_cascade(label="View", menu=view_menu)

    root.config(menu=menu_bar)

    # Bind keyboard shortcuts globally for convenience
    root.bind_all("<Control-n>", lambda e: add_tab())
    root.bind_all("<Control-w>", lambda e: close_current_tab())
    root.bind_all("<Control-f>", lambda e: open_find_dialog())
    root.bind_all("<Control-h>", lambda e: open_find_replace_dialog())

# === Prompt for font size input from user, update active tab's font size ===
def set_font_size_prompt():
    tab = get_current_tab()
    if not tab:
        return
    answer = simpledialog.askinteger("Set Font Size", "Enter font size (6-72):", minvalue=6, maxvalue=72)
    if answer:
        tab["font_size"] = answer
        tab["font"].configure(size=answer)

# === Add a new tab with a text widget and context menu ===
def add_tab(title="Untitled", intro=False):
    frame = tk.Frame(notebook, bg=COLOR_BLACK)
    notebook.add(frame, text=title)
    notebook.select(frame)

    text_font_size = 12
    text_font = font.Font(family="Consolas", size=text_font_size)

    text_area = tk.Text(frame, wrap='word', undo=True,
                        fg=COLOR_SCARLET, bg=COLOR_BLACK,
                        insertbackground=COLOR_SCARLET,
                        selectforeground=COLOR_GOLDEN,
                        selectbackground=COLOR_GREEN_BG,
                        font=text_font)
    text_area.pack(fill='both', expand=True)

    scrollbar = tk.Scrollbar(text_area)
    scrollbar.pack(side='right', fill='y')
    text_area.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=text_area.yview)

    context_menu = tk.Menu(text_area, tearoff=0)
    context_menu.add_command(label="Find", command=lambda: open_find_dialog(text_area))
    context_menu.add_command(label="Find & Replace", command=lambda: open_find_replace_dialog(text_area))
    context_menu.add_separator()
    context_menu.add_command(label="Close Tab", command=close_current_tab)

    def show_context_menu(event):
        context_menu.tk_popup(event.x_root, event.y_root)
    text_area.bind("<Button-3>", show_context_menu)

    # Bind mousewheel zoom for font size control
    text_area.bind("<Control-MouseWheel>", lambda e: on_ctrl_mousewheel(e, text_area))
    text_area.bind("<Control-Button-4>", lambda e: on_ctrl_mousewheel(e, text_area))
    text_area.bind("<Control-Button-5>", lambda e: on_ctrl_mousewheel(e, text_area))

    # Bracket highlights runs after key and mouse release asynchronously
    text_area.bind("<KeyRelease>", lambda e: run_thread(highlight_match, args=(text_area,)))
    text_area.bind("<ButtonRelease>", lambda e: run_thread(highlight_match, args=(text_area,)))

    # Configure tags used for highlighting searched text and matching brackets
    text_area.tag_config("highlight", foreground=COLOR_HIGHLIGHT_FG, background=COLOR_HIGHLIGHT_BG)
    text_area.tag_config("match", foreground=COLOR_GOLDEN, background=COLOR_GREEN_BG)
    # Override default selection colors with golden on green per user request
    text_area.config(selectforeground=COLOR_GOLDEN, selectbackground=COLOR_GREEN_BG)

    filename = None

    if intro:
        intro_text = (
            "Welcome to Scarlet on Black Notepad!\n\n"
            "Instructions:\n"
            "- Hold CTRL + Mouse Wheel to adjust font size quickly.\n"
            "- Right-click for Find, Find & Replace, Close Tab.\n"
            "- Multiple tabs supported.\n"
            "- Default text scarlet on black.\n"
            "- Selection & highlights golden on green.\n"
            "- Files saved encrypted in JSON dict format.\n"
        )
        text_area.insert("1.0", intro_text)

    tabs.append({"frame": frame, "text_area": text_area,
                 "font": text_font, "font_size": text_font_size,
                 "filename": filename})

# === Return dict for currently selected tab or None if none ===
def get_current_tab():
    sel = notebook.select()
    i = 0
    while i < len(tabs):
        if str(tabs[i]["frame"]) == str(sel):
            return tabs[i]
        i += 1
    return None

# === Close the current active tab ===
def close_current_tab():
    tab = get_current_tab()
    if not tab:
        return
    idx = 0
    while idx < len(tabs):
        if tabs[idx] == tab:
            break
        idx += 1
    notebook.forget(tab["frame"])  # Remove the tab frame widget
    del tabs[idx]                  # Remove tab data dict
    if len(tabs) > 0:
        # Select a neighboring tab
        new_idx = idx - 1 if idx > 0 else 0
        notebook.select(tabs[new_idx]["frame"])

# === Ctrl + Mouse wheel changes font size ===
def on_ctrl_mousewheel(event, text_widget):
    tab = None
    i = 0
    while i < len(tabs):
        if tabs[i]["text_area"] == text_widget:
            tab = tabs[i]
            break
        i += 1
    if not tab:
        return "break"
    delta = 0
    if hasattr(event, 'delta'):
        delta = event.delta
    elif event.num == 4:
        delta = 120
    elif event.num == 5:
        delta = -120
    if delta > 0 and tab["font_size"] < 72:
        tab["font_size"] += 1
        tab["font"].configure(size=tab["font_size"])
    elif delta < 0 and tab["font_size"] > 6:
        tab["font_size"] -= 1
        tab["font"].configure(size=tab["font_size"])
    return "break"

# === Helper to run functions in threads for responsiveness ===
def run_thread(func, args=()):
    threading.Thread(target=func, args=args, daemon=True).start()

# === Process UI update functions queued from worker threads ===
def process_ui_queue():
    while True:
        try:
            func = ui_queue.get_nowait()
        except:
            break
        try:
            func()
        except:
            pass
    root.after(100, process_ui_queue)  # Reschedule itself

# === Open file, detect encryption, prompt password if needed, load text ===
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if not file_path:
        return
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        is_encrypted = False
        try:
            j = json.loads(data.decode('utf-8'))
            is_encrypted = all(k in j for k in ('salt','nonce','tag','ciphertext'))
        except:
            is_encrypted = False
        if is_encrypted:
            password = None
            while True:
                password = simpledialog.askstring("Password", "Enter password to decrypt file:", show="*")
                if password is None:
                    return
                try:
                    text = decrypt_text(data, password)
                    break
                except Exception:
                    messagebox.showerror("Error", "Wrong password or corrupted file, try again.")
        else:
            text = data.decode('utf-8')
        def update_tab():
            add_tab(os.path.basename(file_path))
            tab = get_current_tab()
            if tab:
                tab["text_area"].delete("1.0", "end")
                tab["text_area"].insert("1.0", text)
                tab["filename"] = file_path
                notebook.tab(tab["frame"], text=os.path.basename(file_path))
        ui_queue.put(update_tab)
    except Exception as e:
        messagebox.showerror("Error", "Failed to open file:\n" + str(e))

# === Save current tab to its filename or prompt Save As ===
def save_file():
    tab = get_current_tab()
    if not tab:
        return
    if tab["filename"]:
        save_file_to_path(tab["filename"], tab)
    else:
        save_as_file()

# === Prompt Save As dialog for current tab ===
def save_as_file():
    tab = get_current_tab()
    if not tab:
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("All Files", "*.*")])
    if not file_path:
        return
    save_file_to_path(file_path, tab)

# === Save file at path with encryption and password prompt ===
def save_file_to_path(file_path, tab):
    password = simpledialog.askstring("Password", "Enter password to encrypt file:", show="*")
    if password is None:
        return
    content = tab["text_area"].get("1.0", "end-1c")
    def encrypt_and_save():
        try:
            enc_data = encrypt_text(content, password)
            with open(file_path, "wb") as f:
                f.write(enc_data)
            def update_ui():
                tab["filename"] = file_path
                notebook.tab(tab["frame"], text=os.path.basename(file_path))
                messagebox.showinfo("Save", "File encrypted and saved successfully!")
            ui_queue.put(update_ui)
        except Exception as err:
            def show_err():
                messagebox.showerror("Error", "Failed to save file:\n"+ str(err))
            ui_queue.put(show_err)
    run_thread(encrypt_and_save)

# === Highlight matching brackets around cursor ===
def highlight_match(text_widget):
    def remove_tag():
        text_widget.tag_remove("match", "1.0", "end")
    ui_queue.put(remove_tag)

    pairs = {'(': ')', '[': ']', '{': '}'}
    pos = get_safe_index(text_widget, "insert")
    if not pos:
        return
    line = int(pos.split('.')[0])
    col = int(pos.split('.')[1])

    def get_char_at(idx):
        try:
            return text_widget.get(idx, idx + "+1c")
        except:
            return ""

    char_left = get_char_at(f"{line}.{col-1}") if col > 0 else ""
    char_right = get_char_at(f"{line}.{col}")

    def add_tag(start, end):
        def add():
            text_widget.tag_add("match", start, end)
        ui_queue.put(add)

    if char_left in pairs:
        match_idx = find_matching_bracket(text_widget, pos, char_left, pairs[char_left], True)
        if match_idx:
            add_tag(f"{line}.{col-1}", f"{line}.{col}")
            add_tag(match_idx, f"{match_idx}+1c")
    elif char_right in pairs.values():
        reverse_pairs = {v:k for k,v in pairs.items()}
        match_idx = find_matching_bracket(text_widget, pos, char_right, reverse_pairs[char_right], False)
        if match_idx:
            add_tag(f"{line}.{col}", f"{line}.{col+1}")
            add_tag(match_idx, f"{match_idx}+1c")

# === Find matching bracket position, forward or backward ===
def find_matching_bracket(text_widget, pos, char, match_char, forward):
    stack = 1
    idx = get_safe_index(text_widget, pos)
    if not idx:
        return None
    last_idx = idx
    while True:
        try:
            next_idx = get_safe_index(text_widget, last_idx + ("+1c" if forward else "-1c"))
        except:
            return None
        if forward:
            if text_widget.compare(next_idx, ">=", "end"):
                break
        else:
            if text_widget.compare(next_idx, "<", "1.0"):
                break
        c = text_widget.get(next_idx, next_idx + "+1c")
        if c == char:
            stack += 1
        elif c == match_char:
            stack -= 1
            if stack == 0:
                return next_idx
        last_idx = next_idx
    return None

def get_safe_index(text_widget, idx):
    try:
        return text_widget.index(idx)
    except:
        return None

# === Find dialog ===
def open_find_dialog(text_widget=None):
    tab = get_current_tab()
    if text_widget is None and tab:
        text_widget = tab["text_area"]
    elif text_widget is None:
        return

    dlg = tk.Toplevel(root)
    dlg.title("Find")
    dlg.resizable(False, False)
    dlg.transient(root)

    tk.Label(dlg, text="Find:").grid(row=0, column=0, padx=5, pady=5)
    find_entry = tk.Entry(dlg, width=30)
    find_entry.grid(row=0, column=1, padx=5, pady=5)
    find_entry.focus_set()

    def find_next():
        s = find_entry.get()
        if s == "":
            return
        def do_find():
            text_widget.tag_remove("highlight", "1.0", "end")
            start_pos = text_widget.index(tk.INSERT)
            idx = text_widget.search(s, start_pos, "end", nocase=1)
            if idx == "":
                idx = text_widget.search(s, "1.0", "end", nocase=1)
                if idx == "":
                    ui_queue.put(lambda: messagebox.showinfo("Find", f"'{s}' not found."))
                    return
            end_idx = f"{idx}+{len(s)}c"
            text_widget.tag_add("highlight", idx, end_idx)
            text_widget.tag_config("highlight", foreground=COLOR_HIGHLIGHT_FG, background=COLOR_HIGHLIGHT_BG)
            text_widget.mark_set(tk.INSERT, end_idx)
            text_widget.see(idx)
        run_thread(do_find)

    btn_find = tk.Button(dlg, text="Find Next", command=find_next)
    btn_find.grid(row=1, column=0, columnspan=2, pady=5)

    def close_dlg():
        text_widget.tag_remove("highlight", "1.0", "end")
        dlg.destroy()

    dlg.protocol("WM_DELETE_WINDOW", close_dlg)

# === Find & Replace dialog ===
def open_find_replace_dialog(text_widget=None):
    tab = get_current_tab()
    if text_widget is None and tab:
        text_widget = tab["text_area"]
    elif text_widget is None:
        return

    dlg = tk.Toplevel(root)
    dlg.title("Find & Replace")
    dlg.geometry("350x150")
    dlg.resizable(False, False)
    dlg.transient(root)

    tk.Label(dlg, text="Find:").grid(row=0, column=0, sticky='e', padx=5, pady=5)
    find_entry = tk.Entry(dlg, width=30)
    find_entry.grid(row=0, column=1, padx=5, pady=5)
    find_entry.focus_set()

    tk.Label(dlg, text="Replace:").grid(row=1, column=0, sticky='e', padx=5, pady=5)
    replace_entry = tk.Entry(dlg, width=30)
    replace_entry.grid(row=1, column=1, padx=5, pady=5)

    def find_next():
        s = find_entry.get()
        if s == "":
            return
        def do_find():
            text_widget.tag_remove("highlight", "1.0", "end")
            start_pos = text_widget.index(tk.INSERT)
            idx = text_widget.search(s, start_pos, "end", nocase=1)
            if idx == "":
                idx = text_widget.search(s, "1.0", "end", nocase=1)
                if idx == "":
                    ui_queue.put(lambda: messagebox.showinfo("Find", f"'{s}' not found."))
                    return
            end_idx = f"{idx}+{len(s)}c"
            text_widget.tag_add("highlight", idx, end_idx)
            text_widget.tag_config("highlight", foreground=COLOR_HIGHLIGHT_FG, background=COLOR_HIGHLIGHT_BG)
            text_widget.mark_set(tk.INSERT, end_idx)
            text_widget.see(idx)
        run_thread(do_find)

    def replace_one():
        s = find_entry.get()
        r = replace_entry.get()
        if s == "":
            return
        def do_replace_one():
            pos = text_widget.index(tk.INSERT)
            idx = text_widget.search(s, pos, "end", nocase=1)
            if idx == "":
                ui_queue.put(lambda: messagebox.showinfo("Replace", f"'{s}' not found."))
                return
            end_idx = f"{idx}+{len(s)}c"
            text_widget.delete(idx, end_idx)
            text_widget.insert(idx, r)
            new_end = f"{idx}+{len(r)}c"
            text_widget.tag_remove("highlight", "1.0", "end")
            text_widget.tag_add("highlight", idx, new_end)
            text_widget.tag_config("highlight", foreground=COLOR_HIGHLIGHT_FG, background=COLOR_HIGHLIGHT_BG)
            text_widget.mark_set(tk.INSERT, new_end)
            text_widget.see(idx)
            ui_queue.put(lambda: messagebox.showinfo("Replace", "One occurrence replaced."))
        run_thread(do_replace_one)

    def replace_all():
        s = find_entry.get()
        r = replace_entry.get()
        if s == "":
            return
        def do_replace_all():
            content = text_widget.get("1.0", "end-1c")
            flags = re.IGNORECASE
            matches = []
            try:
                matches = list(re.finditer(re.escape(s), content, flags=flags))
            except:
                ui_queue.put(lambda: messagebox.showerror("Error", "Invalid find pattern."))
                return
            count = len(matches)
            if count == 0:
                ui_queue.put(lambda: messagebox.showinfo("Replace All", f"'{s}' not found."))
                return
            new_content = re.sub(re.escape(s), r, content, flags=flags)
            text_widget.delete("1.0", "end")
            text_widget.insert("1.0", new_content)
            text_widget.tag_remove("highlight", "1.0", "end")
            start_index = "1.0"
            replaced = 0
            while replaced < count:
                idx = text_widget.search(r, start_index, "end", nocase=1)
                if idx == "":
                    break
                end_idx = f"{idx}+{len(r)}c"
                text_widget.tag_add("highlight", idx, end_idx)
                text_widget.tag_config("highlight", foreground=COLOR_HIGHLIGHT_FG, background=COLOR_HIGHLIGHT_BG)
                start_index = end_idx
                replaced += 1
            ui_queue.put(lambda: messagebox.showinfo("Replace All", f"{count} occurrences replaced."))
        run_thread(do_replace_all)

    btn_find = tk.Button(dlg, text="Find Next", command=find_next)
    btn_find.grid(row=2, column=0, padx=5, pady=5)

    btn_replace = tk.Button(dlg, text="Replace", command=replace_one)
    btn_replace.grid(row=2, column=1, sticky='w', padx=5, pady=5)

    btn_replace_all = tk.Button(dlg, text="Replace All", command=replace_all)
    btn_replace_all.grid(row=3, column=0, columnspan=2, pady=5)

    def close_dlg():
        text_widget.tag_remove("highlight", "1.0", "end")
        dlg.destroy()
    dlg.protocol("WM_DELETE_WINDOW", close_dlg)

def undo_edit():
    tab = get_current_tab()
    if tab is None:
        return
    try:
        tab["text_area"].edit_undo()
    except:
        pass

def redo_edit():
    tab = get_current_tab()
    if tab is None:
        return
    try:
        tab["text_area"].edit_redo()
    except:
        pass

def next_tab(event=None):
    count = len(tabs)
    if count <= 1:
        return "break"
    current = notebook.index(notebook.select())
    notebook.select((current + 1) % count)
    return "break"

def prev_tab(event=None):
    count = len(tabs)
    if count <= 1:
        return "break"
    current = notebook.index(notebook.select())
    notebook.select((current - 1) % count)
    return "break"

def main():
    create_main_window()
    root.mainloop()

if __name__ == "__main__":
    main()
