import argparse
import datetime
import os
import sqlite3
import struct
import time
import zipfile
import tarfile
import sys
import hashlib
import threading
import subprocess
import tkinter as tk
from tkinter import filedialog, scrolledtext, Menu
import webbrowser

# Attempt to load GUI-specific libraries
try:
    import customtkinter as ctk
    from PIL import Image, ImageTk
    GUI_SUPPORT = True
except ImportError:
    GUI_SUPPORT = False

# --- Global Configurations ---
arc_version = "v2.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IMAGE_PATH = os.path.join(BASE_DIR, "assets", "Arc2Lite.png")
ICON_PATH = os.path.join(BASE_DIR, "assets", "stark4n6.ico")

ascii_art = fr'''
     _             ____  _     _ _       
    / \   _ __ ___|___ \| |   (_) |_ ___ 
   / _ \ | '__/ __| __) | |   | | __/ _ \
  / ___ \| | | (__ / __/| |___| | ||  __/
 /_/   \_\_|  \___|_____|_____|_|\__\___|
                                                                           
Arc2Lite {arc_version}
https://github.com/stark4n6/Arc2Lite
'''

# --- Shared Forensic Logic ---

def get_forensic_type(file_path):
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 512: return None
    ext = file_path.lower()
    try:
        with open(file_path, 'rb') as f:
            header = f.read(512)
            if header.startswith(b'PK\x03\x04') and ext.endswith('.zip'): return "ZIP"
            if header.startswith(b'\x1f\x8b') and ext.endswith('.gz'): return "GZ"
            if header[257:262] == b'ustar' and ext.endswith('.tar'): return "TAR"
    except: return None
    return None

def decode_extended_ts(extra_data):
    offset = 0
    length = len(extra_data)
    while offset < length:
        header_id, data_size = struct.unpack_from('<HH', extra_data, offset)
        offset += 4
        if header_id == 0x5455:
            flags = struct.unpack_from('B', extra_data, offset)[0]
            offset += 1
            ts = {}
            if flags & 1:
                m, = struct.unpack_from('<I', extra_data, offset); ts['m'] = m; offset += 4
            if flags & 2:
                a, = struct.unpack_from('<I', extra_data, offset); ts['a'] = a; offset += 4
            if flags & 4:
                c, = struct.unpack_from('<I', extra_data, offset); ts['c'] = c; offset += 4
            return ts
        else: offset += data_size
    return None

def format_ts(ts):
    if ts is None or (isinstance(ts, (int, float)) and ts <= 315532800): return ''
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()

def setup_db(cursor):
    cursor.execute('''CREATE TABLE IF NOT EXISTS file_listing (
        file_name TEXT, file_extension TEXT, entry_path TEXT COLLATE NOCASE PRIMARY KEY,
        created_date TEXT, modified_date TEXT, accessed_date TEXT,
        is_file INTEGER, size INTEGER, comp_size INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS archive_metadata (
        source_file_name TEXT, source_full_path TEXT, archive_type TEXT,
        file_size_bytes INTEGER, hash_algorithm TEXT, hash_value TEXT,
        extraction_timestamp TEXT)''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_ext ON file_listing (file_extension);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_mod_date ON file_listing (modified_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_name ON file_listing (file_name);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_entry_path ON file_listing (entry_path);")

def calculate_hash_shared(file_path, file_name, file_id, itype, algo, update_func):
    if not algo or algo == "None": return None
    hash_func = hashlib.new(algo)
    chunk_size = 1024 * 1024 
    try:
        file_size = os.path.getsize(file_path)
        processed = 0
        last_update = 0
        update_interval = 100 * 1024 * 1024 
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                hash_func.update(chunk)
                processed += len(chunk)
                if file_size > update_interval and (processed - last_update) >= update_interval:
                    percent = (processed / file_size) * 100
                    update_func(f"    [{file_id}] [{itype}] HASHING {file_name}: {percent:.1f}%\n", replace_last=True)
                    last_update = processed
        update_func(f"    [{file_id}] [{itype}] HASHING {file_name}: 100.0% complete.\n", replace_last=True)
        return hash_func.hexdigest()
    except Exception as e:
        update_func(f"    [!] Hash Error on {file_name}: {e}\n")
        return "HASH_ERROR"

def process_archive_logic(file_path, out_folder, uid, f_type, hash_algo, hash_val):
    db_path = os.path.join(out_folder, f"{uid}-{os.path.basename(file_path)}_file_listing.db")
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            setup_db(cursor)
            cursor.execute('INSERT INTO archive_metadata VALUES (?,?,?,?,?,?,?)',
                (os.path.basename(file_path), file_path, f_type, os.path.getsize(file_path), 
                 hash_algo or "None", hash_val or "N/A", datetime.datetime.now(datetime.timezone.utc).isoformat()))

            if f_type == "ZIP":
                with zipfile.ZipFile(file_path, 'r', allowZip64=True) as arc:
                    for info in arc.infolist():
                        m = datetime.datetime(*info.date_time, tzinfo=datetime.timezone.utc).timestamp()
                        c = a = m 
                        ext = decode_extended_ts(info.extra)
                        if ext:
                            m = ext.get('m', m); a = ext.get('a', m); c = ext.get('c', m)
                        is_f = 1 if not info.filename.endswith('/') else 0
                        cursor.execute("INSERT OR IGNORE INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)",
                                       (os.path.basename(info.filename), os.path.splitext(info.filename)[1], info.filename, 
                                        format_ts(c), format_ts(m), format_ts(a), is_f, info.file_size, info.compress_size))
            elif f_type in ["TAR", "GZ"]:
                mode = "r:gz" if f_type == "GZ" else "r:*"
                with tarfile.open(file_path, mode, errorlevel=0) as arc:
                    for mem in arc:
                        if mem.isfile() or mem.isdir():
                            m = mem.mtime
                            is_f = 1 if mem.isfile() else 0
                            cursor.execute("INSERT OR IGNORE INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)",
                                           (os.path.basename(mem.name), os.path.splitext(mem.name)[1], mem.name, 
                                            format_ts(m), format_ts(m), format_ts(m), is_f, mem.size, None))
            conn.commit()
        return db_path
    except: return None

# --- CLI Implementation ---

def run_cli(args):
    print(ascii_art)
    print(f"--- Processing Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    start_epoch = time.time()
    out_root = os.path.join(args.output, f"Arc2Lite_Out_{time.strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(out_root, exist_ok=True)
    master_db = os.path.join(out_root, "Arc2Lite_Master_Log.db")
    h_col = f"{args.hash}_hash TEXT," if args.hash else ""

    def cli_update(msg, replace_last=False):
        if replace_last: sys.stdout.write(f"\r{msg.strip()}"); sys.stdout.flush()
        else: sys.stdout.write(f"\n{msg}" if not msg.startswith('[') else msg); sys.stdout.flush()

    with sqlite3.connect(master_db) as m_conn:
        m_cursor = m_conn.cursor()
        m_cursor.execute(f"CREATE TABLE processing_log (input_path TEXT, item_type TEXT, {h_col} database_output TEXT, timestamp TEXT)")
        file_id = 1
        for root, _, files in os.walk(args.input):
            for file in files:
                path = os.path.join(root, file); itype = get_forensic_type(path)
                if itype:
                    cli_update(f"[{file_id}] [{itype}] {file}\n")
                    h_val = calculate_hash_shared(path, file, file_id, itype, args.hash, cli_update)
                    db = process_archive_logic(path, out_root, file_id, itype, args.hash, h_val)
                    if db:
                        entry = [path, itype]
                        if args.hash: entry.append(h_val)
                        entry.extend([db, datetime.datetime.now(datetime.timezone.utc).isoformat()])
                        m_cursor.execute(f"INSERT INTO processing_log VALUES ({','.join(['?']*len(entry))})", entry)
                        cli_update(f"--- Archive Processed ---\n\n")
                        file_id += 1
            if not args.recursive: break
        m_conn.commit()
    print(f"\n--- Processing Finished: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
    print(f"**** JOB FINISHED ****\nItems Indexed: {file_id - 1}\nRuntime: {time.time()-start_epoch:.2f}s\nMaster Log: {master_db}")

# --- GUI Implementation ---

if GUI_SUPPORT:
    class Arc2LiteGUI(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.title(f"Arc2Lite {arc_version}")
            if os.path.exists(ICON_PATH): self.after(250, lambda: self.iconbitmap(ICON_PATH))
            self.geometry("850x800")
            self.resizable(False, False)
            self.grid_columnconfigure(0, weight=1)
            self.input_path = tk.StringVar(); self.export_path = tk.StringVar(); self.is_folder = False
            self.hash_choice = tk.StringVar(value="None")
            self.hash_vars = {k: tk.BooleanVar(value=False) for k in ["md5", "sha1", "sha256"]}
            self.create_menu(); self.create_widgets()

        def center_window(self, win, width, height):
            px, py = self.winfo_x(), self.winfo_y()
            pw, ph = self.winfo_width(), self.winfo_height()
            x = px + (pw // 2) - (width // 2)
            y = py + (ph // 2) - (height // 2)
            win.geometry(f"{width}x{height}+{x}+{y}")

        def create_widgets(self):
            try:
                if os.path.exists(IMAGE_PATH):
                    img = Image.open(IMAGE_PATH).resize((180, 180))
                    self.img_tk = ImageTk.PhotoImage(img)
                    ctk.CTkLabel(self, image=self.img_tk, text="").grid(row=0, column=0, pady=5)
            except: pass
            f1 = ctk.CTkFrame(self); f1.grid(row=1, column=0, padx=20, pady=5, sticky="ew")
            ctk.CTkEntry(f1, textvariable=self.input_path).grid(row=0, column=0, padx=(10, 5), pady=10, sticky="ew")
            ctk.CTkButton(f1, text="Folder", width=120, command=self.b_f).grid(row=0, column=1, padx=2)
            ctk.CTkButton(f1, text="Archive", width=120, command=self.b_a).grid(row=0, column=2, padx=(2, 10))
            f1.grid_columnconfigure(0, weight=1)
            f2 = ctk.CTkFrame(self); f2.grid(row=2, column=0, padx=20, pady=5, sticky="ew")
            ctk.CTkEntry(f2, textvariable=self.export_path).grid(row=0, column=0, padx=(10, 5), pady=10, sticky="ew")
            ctk.CTkButton(f2, text="Export", width=120, command=self.b_e).grid(row=0, column=1, padx=(2, 134))
            f2.grid_columnconfigure(0, weight=1)
            f3 = ctk.CTkFrame(self); f3.grid(row=3, column=0, padx=20, pady=5, sticky="ew")
            ctk.CTkLabel(f3, text="Calculate Hash (Optional)", font=ctk.CTkFont(size=13, weight="bold")).pack(pady=(10, 0))
            hc = ctk.CTkFrame(f3, fg_color="transparent"); hc.pack(expand=True)
            for i, (k, v) in enumerate(self.hash_vars.items()):
                ctk.CTkCheckBox(hc, text=k.upper(), variable=v, command=lambda x=k: self.h_c(x)).grid(row=0, column=i, padx=30, pady=10)
            self.btn = ctk.CTkButton(self, text="Start Forensic Indexing", font=ctk.CTkFont(size=14, weight="bold"), command=self.start)
            self.btn.grid(row=4, column=0, padx=20, pady=15, sticky="ew")
            self.out = scrolledtext.ScrolledText(self, height=18); self.out.grid(row=5, column=0, padx=20, pady=10, sticky="nsew")
            self.grid_rowconfigure(5, weight=1)

        def b_f(self): p = filedialog.askdirectory(); self.input_path.set(p); self.is_folder = True
        def b_a(self): p = filedialog.askopenfilename(); self.input_path.set(p); self.is_folder = False
        def b_e(self): p = filedialog.askdirectory(); self.export_path.set(p)
        def h_c(self, s):
            for k, v in self.hash_vars.items(): 
                if k != s: v.set(False)
            self.hash_choice.set(s if self.hash_vars[s].get() else "None")

        def start(self):
            self.btn.configure(state="disabled"); self.out.delete("1.0", tk.END)
            threading.Thread(target=self.run, daemon=True).start()

        def log(self, m, replace_last=False):
            try: self.after(0, lambda: (self.out.delete("end-2l", "end-1l") if replace_last else None, self.out.insert(tk.END, m), self.out.see(tk.END)))
            except: pass

        def run(self):
            self.log(f"--- Processing Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n\n")
            start_epoch = time.time()
            out_root = os.path.join(self.export_path.get(), f"Arc2Lite_Out_{time.strftime('%Y%m%d-%H%M%S')}")
            os.makedirs(out_root, exist_ok=True)
            algo = self.hash_choice.get(); master_db = os.path.join(out_root, "Arc2Lite_Master_Log.db")
            h_col = f"{algo}_hash TEXT," if algo != "None" else ""
            with sqlite3.connect(master_db) as m_conn:
                m_cursor = m_conn.cursor()
                m_cursor.execute(f"CREATE TABLE processing_log (input_path TEXT, item_type TEXT, {h_col} database_output TEXT, timestamp TEXT)")
                file_id = 1
                targets = os.walk(self.input_path.get()) if self.is_folder else [(os.path.dirname(self.input_path.get()), [], [os.path.basename(self.input_path.get())])]
                for root, _, files in targets:
                    for file in files:
                        p = os.path.join(root, file); itype = get_forensic_type(p)
                        if itype:
                            self.log(f"[{file_id}] [{itype}] {file}\n")
                            h_val = calculate_hash_shared(p, file, file_id, itype, algo, self.log)
                            db = process_archive_logic(p, out_root, file_id, itype, algo, h_val)
                            entry = [p, itype]
                            if algo != "None": entry.append(h_val)
                            entry.extend([db, datetime.datetime.now(datetime.timezone.utc).isoformat()])
                            m_cursor.execute(f"INSERT INTO processing_log VALUES ({','.join(['?']*len(entry))})", entry)
                            self.log(f"    --- Archive Processed ---\n\n")
                            file_id += 1
                m_conn.commit()
            self.log(f"--- Processing Finished: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            self.after(0, lambda: self.finish_dialog(out_root, file_id-1, start_epoch))

        def finish_dialog(self, root, count, start_epoch):
            self.log(f"**** JOB FINISHED ****\nItems Indexed: {count}\nRuntime: {time.time()-start_epoch:.2f}s")
            self.btn.configure(state="normal")
            
            # Centered Custom Completion Dialog
            fin = ctk.CTkToplevel(self); fin.title("Job Complete"); self.center_window(fin, 320, 150)
            fin.resizable(False, False); fin.transient(self); fin.grab_set()
            if os.path.exists(ICON_PATH): fin.iconbitmap(ICON_PATH)
            
            ctk.CTkLabel(fin, text=f"Processed {count} items successfully.", font=("Arial", 13)).pack(pady=(20, 10))
            btn_frame = ctk.CTkFrame(fin, fg_color="transparent"); btn_frame.pack(pady=10)
            
            def open_and_close():
                os.startfile(root) if os.name == 'nt' else subprocess.Popen(['xdg-open', root])
                fin.destroy()

            ctk.CTkButton(btn_frame, text="Open Folder", width=100, command=open_and_close).grid(row=0, column=0, padx=10)
            ctk.CTkButton(btn_frame, text="Close", width=100, command=fin.destroy).grid(row=0, column=1, padx=10)

        def create_menu(self):
            m = Menu(self); f = Menu(m, tearoff=0); f.add_command(label="Exit", command=self.destroy); m.add_cascade(label="File", menu=f)
            h = Menu(m, tearoff=0); h.add_command(label="About", command=self.show_about); m.add_cascade(label="Help", menu=h)
            self.config(menu=m)
            
        def show_about(self):
            abt = ctk.CTkToplevel(self); abt.title("About Arc2Lite"); self.center_window(abt, 300, 170)
            abt.resizable(False, False); abt.transient(self); abt.grab_set()
            if os.path.exists(ICON_PATH): abt.iconbitmap(ICON_PATH)
            ctk.CTkLabel(abt, text=f"Arc2Lite {arc_version}").pack(pady=(15, 0))
            ctk.CTkLabel(abt, text="Created by @KevinPagano3 | @stark4n6").pack(pady=5)
            url = "https://github.com/stark4n6/Arc2Lite"
            link = tk.Label(abt, text=url, fg="blue", cursor="hand2", font=("TkDefaultFont", 10, "underline"))
            link.pack(pady=5); link.bind("<Button-1>", lambda e: webbrowser.open_new(url))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(ascii_art)
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--input", required=True); parser.add_argument("-o", "--output", required=True)
        parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan folder for archives"); parser.add_argument("-ha", "--hash", choices=['md5', 'sha1', 'sha256'], help="Optional hashing options")
        run_cli(parser.parse_args())
    else:
        if GUI_SUPPORT: app = Arc2LiteGUI(); app.mainloop()
        else: print("GUI libraries not found. Use CLI switches.")