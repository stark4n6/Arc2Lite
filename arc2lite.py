import argparse
import calendar
import csv
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
import webbrowser

# Attempt to load GUI-specific libraries. tkinter is in the standard library
# but Tk itself is not always built with Python: a headless Linux server and
# some Homebrew builds have no _tkinter, and importing it at the top of the
# file stopped the command line running there at all.
try:
    import tkinter as tk
    from tkinter import filedialog, scrolledtext, Menu
    import customtkinter as ctk
    from PIL import Image, ImageTk
    GUI_SUPPORT = True
except ImportError:
    GUI_SUPPORT = False

# Disk image and EnCase/EWF input. The readers behind it are vendored in
# vendor/ and are standard library only, so this needs nothing installed; it is
# still optional, and without it Arc2Lite reads archives exactly as before.
try:
    import disk_image
    IMAGE_SUPPORT = True
except ImportError:
    IMAGE_SUPPORT = False

# --- Global Configurations ---
arc_version = "v3.2.0"
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

def normalize_separators(path_str):
    if not path_str:
        return path_str
    target_sep = '\\' if os.name == 'nt' else '/'
    return path_str.replace('/', target_sep).replace('\\', target_sep)

def get_forensic_type(file_path):
    if not os.path.isfile(file_path) or os.path.getsize(file_path) < 512: return None
    ext = file_path.lower()
    try:
        with open(file_path, 'rb') as f:
            header = f.read(512)
            if header.startswith(b'PK\x03\x04') and ext.endswith('.zip'): return "ZIP"
            if header.startswith(b'\x1f\x8b') and ext.endswith('.gz'): return "GZ"
            if header.startswith(b'\xfd7zXZ\x00') and ext.endswith('.xz'): return "XZ"
            if header[257:262] == b'ustar' and ext.endswith('.tar'): return "TAR"
    except: return None
    # A raw disk image or an EnCase/EWF acquisition. Decided by reading the
    # image rather than by its name: a file with an image extension that holds
    # no volume this reader recognises is not claimed. A later segment of a
    # split set returns None, so a set is indexed once, from its first segment.
    if IMAGE_SUPPORT:
        return disk_image.detect(file_path)
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

def _reading_to_epoch(s):
    """Convert one of file_listing's date strings to whole seconds since the
    epoch, the resolution a bodyfile's atime/mtime/ctime/crtime columns need.

    file_listing carries three shapes, depending on what wrote the row:
      - a full ISO 8601 instant with a UTC offset, e.g.
        "2024-01-01T00:00:00+00:00" (format_ts()/disk_image.format_instant())
        - a real instant.
      - a FAT/exFAT "stored reading": space-separated, no offset, e.g.
        "2024-01-01 00:00:00.50" (vendor/qnxprobe.py's _dos_stamp()/
        _exfat_stamp()) - a zone-less wall clock, not an instant (see this
        README's "About the dates").
      - a FAT date-only reading with no time at all, e.g. "2024-01-01"
        (vendor/qnxprobe.py's _dos_date()).
    Empty string (no data recorded) and anything unparseable become 0,
    mactime's usual "no time" value.

    This parses the digits directly with calendar.timegm() rather than
    datetime.fromisoformat(): fromisoformat() only accepts exactly 3 or 6
    fractional-second digits on the Python versions this project supports
    down to 3.9, and a FAT/exFAT reading's hundredths ("00:00:00.50") has
    neither; it would also apply the *host's* timezone to a zone-less
    reading if not handled as UTC-shaped digits explicitly, giving a
    different answer on every machine for the same evidence.
    """
    if not s:
        return 0
    s = s.strip()
    if not s:
        return 0
    sep = 'T' if 'T' in s else (' ' if ' ' in s else None)
    if sep is None:
        date_part, time_part, offset = s, '', ''
    else:
        date_part, _, rest = s.partition(sep)
        if '+' in rest:
            time_part, _, off = rest.partition('+')
            offset = '+' + off
        elif sep == 'T' and rest.count('-') and rest.rfind('-') > 0:
            # A UTC offset written as "-HH:MM" only ever appears after "T"
            # (format_ts()/format_instant()); a space-separated reading
            # never carries one.
            idx = rest.rfind('-')
            time_part, offset = rest[:idx], rest[idx:]
        else:
            time_part, offset = rest, ''
        time_part = time_part.split('.')[0]  # drop fractional seconds/hundredths

    try:
        y, m, d = (int(x) for x in date_part.split('-'))
    except ValueError:
        return 0
    hh = mm = ss = 0
    if time_part:
        try:
            parts = [int(x) for x in time_part.split(':')]
            hh, mm, ss = (parts + [0, 0])[:3]
        except ValueError:
            pass
    try:
        epoch = calendar.timegm((y, m, d, hh, mm, ss, 0, 0, 0))
    except (ValueError, OverflowError):
        return 0
    if offset:
        try:
            sign = 1 if offset[0] == '+' else -1
            oh, om = (int(x) for x in offset[1:].split(':'))
            epoch -= sign * (oh * 3600 + om * 60)
        except ValueError:
            pass
    return epoch

def export_bodyfile(db_path, update=None):
    """Write file_listing out as a Sleuth Kit/mactime bodyfile -
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime,
    one line per row - to '<db file name>.body' beside db_path. Returns the
    path written, or None if db_path has no file_listing table to read (the
    master log, for instance) or file_listing has no rows.

    There's no Arc2Lite equivalent of an inode change time, so ctime is
    always 0. md5, inode, uid and gid aren't tracked either and are always 0.
    """
    if update is None:
        update = lambda msg, replace_last=False: None
    conn = sqlite3.connect(db_path)
    try:
        try:
            cursor = conn.execute(
                "SELECT entry_path, is_file, size, created_date, modified_date, "
                "accessed_date FROM file_listing")
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            return None
    finally:
        conn.close()
    if not rows:
        return None
    stem = db_path[:-3] if db_path.lower().endswith(".db") else db_path
    body_path = f"{stem}.body"
    try:
        with open(body_path, 'w', newline='', encoding='utf-8') as f:
            for entry_path, is_file, size, created, modified, accessed in rows:
                # Bodyfiles are pipe-delimited and traditionally forward-slashed,
                # regardless of what normalize_separators() gave the path for
                # the platform Arc2Lite ran on.
                name = (entry_path or '').replace('\\', '/').replace('|', '_')
                mode = "r/rrwxrwxrwx" if is_file else "d/drwxrwxrwx"
                atime = _reading_to_epoch(accessed)
                mtime = _reading_to_epoch(modified)
                crtime = _reading_to_epoch(created)
                f.write(f"0|{name}|0|{mode}|0|0|{size or 0}|{atime}|{mtime}|0|{crtime}\n")
    except OSError as e:
        update(f"    [!] Failed to write bodyfile: {e}\n")
        return None
    return body_path

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

def export_tables_to_csv(db_path, update=None):
    """Export every table in the SQLite database at db_path to its own CSV
    file, written into a '<db file name>_csv' folder beside it. Returns the
    list of CSV paths written.

    This reads back whatever process_archive_logic (or the master log) just
    committed, so it works the same for an archive's file_listing/
    archive_metadata, an image's extra image_* tables, and the master log's
    processing_log, without needing to know which tables exist.
    """
    if update is None:
        update = lambda msg, replace_last=False: None
    stem = db_path[:-3] if db_path.lower().endswith(".db") else db_path
    csv_dir = f"{stem}_csv"
    os.makedirs(csv_dir, exist_ok=True)
    written = []
    # A plain "with sqlite3.connect(...) as conn" only commits/rolls back on
    # exit, it does not close the connection. Windows keeps the database file
    # locked for as long as that handle is open, which then fails a caller
    # trying to move or delete it (a temp-dir cleanup, a re-run into the same
    # output folder), so this closes explicitly rather than waiting on
    # garbage collection to get around to it.
    conn = sqlite3.connect(db_path)
    try:
        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for table in tables:
            csv_path = os.path.join(csv_dir, f"{table}.csv")
            try:
                cursor = conn.execute(f'SELECT * FROM "{table}"')
                headers = [d[0] for d in cursor.description]
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(cursor)
                written.append(csv_path)
            except Exception as e:
                update(f"    [!] Failed to write CSV for {table}: {e}\n")
    finally:
        conn.close()
    return written

def apply_export_choice(db_path, export, update=None):
    """Act on --export/-e (or the GUI's matching SQLite/CSV/Timeline
    checkboxes) for one database. export is one or more of 'sqlite', 'csv',
    'timeline': 'sqlite' keeps db_path exactly as process_archive_logic()
    (or the master log) wrote it, 'csv' also writes every table out as its
    own CSV, and 'timeline' also writes a Sleuth Kit/mactime bodyfile from
    file_listing. Any combination can be chosen together (e.g. csv+timeline
    with no sqlite), and db_path is removed afterward unless 'sqlite' was
    one of the choices.

    The database is always built first regardless of choice: it is what
    gives file_listing its row-per-entry_path dedup (INSERT OR IGNORE against
    a NOCASE PRIMARY KEY), which a straight-to-CSV or straight-to-bodyfile
    write during the walk would not have. Every choice other than 'sqlite'
    alone is therefore "build it, export it, then clean up the working file"
    rather than "never build it".

    A database with no file_listing table (the master log) silently
    produces no bodyfile when 'timeline' is chosen -- export_bodyfile()
    already treats that as a no-op -- so this needs no special case to keep
    'timeline' scoped to per-archive/image databases only.
    """
    if update is None:
        update = lambda msg, replace_last=False: None
    export = set(export) if export else {"sqlite"}
    if "timeline" in export:
        export_bodyfile(db_path, update)
    if "csv" in export:
        export_tables_to_csv(db_path, update)
    if "sqlite" not in export:
        try:
            os.remove(db_path)
        except OSError as e:
            update(f"    [!] Left {os.path.basename(db_path)} in place, could not remove it: {e}\n")

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

def process_archive_logic(file_path, out_folder, uid, f_type, hash_algo, hash_val, update=None):
    db_path = os.path.join(out_folder, f"{uid}-{os.path.basename(file_path)}_file_listing.db")
    if update is None:
        update = lambda msg, replace_last=False: None
    # sqlite3.connect() used as "with conn:" only commits/rolls back on exit,
    # it does not close the connection. Windows keeps the .db file locked for
    # as long as that handle is open, which then fails a caller trying to
    # move or delete it, so this closes explicitly in a finally rather than
    # waiting on garbage collection to get around to it.
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        setup_db(cursor)
        
        # Apply the path normalization to the full file_path before inserting it into the archive_metadata table
        normalized_source_path = normalize_separators(file_path)
        
        cursor.execute('INSERT INTO archive_metadata VALUES (?,?,?,?,?,?,?)',
            (os.path.basename(file_path), normalized_source_path, f_type, os.path.getsize(file_path),
             hash_algo or "None", hash_val or "N/A", datetime.datetime.now(datetime.timezone.utc).isoformat()))

        if f_type in ("RAW", "E01"):
            # A disk image holds its file listing behind a filesystem
            # instead of behind a central directory. Same rows, same
            # table, plus the image_* tables for what a volume has and an
            # archive does not.
            disk_image.index_image(file_path, cursor, f_type, update)
        elif f_type == "ZIP":
            with zipfile.ZipFile(file_path, 'r', allowZip64=True) as arc:
                for info in arc.infolist():
                    m = datetime.datetime(*info.date_time, tzinfo=datetime.timezone.utc).timestamp()
                    c = a = m
                    ext = decode_extended_ts(info.extra)
                    if ext:
                        m = ext.get('m', m); a = ext.get('a', m); c = ext.get('c', m)
                    is_f = 1 if not info.filename.endswith('/') else 0
                    
                    normalized_entry = normalize_separators(info.filename)
                    
                    cursor.execute("INSERT OR IGNORE INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)",
                                   (os.path.basename(info.filename), os.path.splitext(info.filename)[1], normalized_entry,
                                    format_ts(c), format_ts(m), format_ts(a), is_f, info.file_size, info.compress_size))
        elif f_type in ["TAR", "GZ", "XZ"]:
            mode = "r:gz" if f_type == "GZ" else ("r:xz" if f_type == "XZ" else "r:*")
            with tarfile.open(file_path, mode, errorlevel=0) as arc:
                for mem in arc:
                    if mem.isfile() or mem.isdir():
                        m = mem.mtime
                        is_f = 1 if mem.isfile() else 0
                        
                        normalized_entry = normalize_separators(mem.name)
                        
                        cursor.execute("INSERT OR IGNORE INTO file_listing VALUES (?,?,?,?,?,?,?,?,?)",
                                       (os.path.basename(mem.name), os.path.splitext(mem.name)[1], normalized_entry,
                                        format_ts(m), format_ts(m), format_ts(m), is_f, mem.size, None))
        conn.commit()
        return db_path
    except Exception as e:
        update(f"    [!] Failed to index {os.path.basename(file_path)}: {e}\n")
        return None
    finally:
        if conn is not None:
            conn.close()

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

    m_conn = sqlite3.connect(master_db)
    try:
        m_cursor = m_conn.cursor()
        m_cursor.execute(f"CREATE TABLE processing_log (input_path TEXT, item_type TEXT, {h_col} database_output TEXT, timestamp TEXT)")
        file_id = 1
        # A folder is swept; a single file is indexed on its own, which is how
        # one archive or one disk image is handed in.
        if os.path.isfile(args.input):
            targets = [(os.path.dirname(os.path.abspath(args.input)), [],
                        [os.path.basename(args.input)])]
        else:
            targets = os.walk(args.input)
        for root, _, files in targets:
            for file in files:
                path = os.path.join(root, file); itype = get_forensic_type(path)
                if itype:
                    cli_update(f"[{file_id}] [{itype}] {file}\n")
                    h_val = calculate_hash_shared(path, file, file_id, itype, args.hash, cli_update)
                    db = process_archive_logic(path, out_root, file_id, itype, args.hash, h_val, cli_update)
                    if db:
                        apply_export_choice(db, args.export, cli_update)

                        # Apply normalization to the master log entry as well
                        normalized_log_path = normalize_separators(path)
                        entry = [normalized_log_path, itype]
                        
                        if args.hash: entry.append(h_val)
                        
                        normalized_db_path = normalize_separators(db)
                        entry.extend([normalized_db_path, datetime.datetime.now(datetime.timezone.utc).isoformat()])
                        
                        m_cursor.execute(f"INSERT INTO processing_log VALUES ({','.join(['?']*len(entry))})", entry)
                        cli_update(f"--- Item Processed ---\n\n")
                        file_id += 1
            if not args.recursive: break
        m_conn.commit()
    finally:
        # Closed explicitly (see process_archive_logic) since export_tables_to_csv()
        # below opens its own connection to this same master_db file right after.
        m_conn.close()
    apply_export_choice(master_db, args.export, cli_update)
    # 'sqlite' not being one of the choices removes master_db itself; point
    # the summary at whatever's actually left on disk rather than a path
    # that no longer exists.
    export_set = set(args.export) if args.export else {"sqlite"}
    if "sqlite" in export_set:
        master_log_display = master_db
    elif "csv" in export_set:
        master_log_display = f"{master_db[:-3]}_csv"
    else:
        master_log_display = "(not written -- neither sqlite nor csv was selected)"
    print(f"\n--- Processing Finished: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
    print(f"**** JOB FINISHED ****\nItems Indexed: {file_id - 1}\nRuntime: {time.time()-start_epoch:.2f}s\nMaster Log: {master_log_display}")

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
            # Matches -e/--export's choices: one or more of sqlite, csv,
            # timeline. SQLite is on by default, same as the CLI's default.
            self.export_vars = {
                "sqlite": tk.BooleanVar(value=True),
                "csv": tk.BooleanVar(value=False),
                "timeline": tk.BooleanVar(value=False),
            }
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
            
            f_paths = ctk.CTkFrame(self)
            f_paths.grid(row=1, column=0, padx=20, pady=5, sticky="ew")
            f_paths.grid_columnconfigure(0, weight=1)

            ctk.CTkEntry(f_paths, textvariable=self.input_path).grid(row=0, column=0, padx=(10, 5), pady=(10, 5), sticky="ew")
            ctk.CTkButton(f_paths, text="Folder", width=120, command=self.b_f).grid(row=0, column=1, padx=2, pady=(10, 5))
            ctk.CTkButton(f_paths, text="Archive/Evidence File", command=self.b_a).grid(row=0, column=2, padx=(2, 10), pady=(10, 5))

            ctk.CTkEntry(f_paths, textvariable=self.export_path).grid(row=1, column=0, padx=(10, 5), pady=(5, 10), sticky="ew")
            ctk.CTkButton(f_paths, text="Export", width=120, command=self.b_e).grid(row=1, column=1, padx=2, pady=(5, 10))

            f3 = ctk.CTkFrame(self); f3.grid(row=2, column=0, padx=20, pady=5, sticky="ew")
            ctk.CTkLabel(f3, text="Calculate Hash (Optional)", font=ctk.CTkFont(size=13, weight="bold")).pack(pady=(10, 0))
            hc = ctk.CTkFrame(f3, fg_color="transparent"); hc.pack(expand=True)
            for i, (k, v) in enumerate(self.hash_vars.items()):
                ctk.CTkCheckBox(hc, text=k.upper(), variable=v, command=lambda x=k: self.h_c(x)).grid(row=0, column=i, padx=30, pady=10)
            ctk.CTkLabel(f3, text="Export Format", font=ctk.CTkFont(size=13, weight="bold")).pack(pady=(5, 0))
            ef = ctk.CTkFrame(f3, fg_color="transparent"); ef.pack(pady=(5, 10))
            for i, (key, label) in enumerate(
                    [("sqlite", "SQLite"), ("csv", "CSV"), ("timeline", "Timeline (.body)")]):
                ctk.CTkCheckBox(ef, text=label, variable=self.export_vars[key]).grid(row=0, column=i, padx=15)

            self.btn = ctk.CTkButton(self, text="Start Forensic Indexing", font=ctk.CTkFont(size=14, weight="bold"), command=self.start)
            self.btn.grid(row=3, column=0, padx=20, pady=15, sticky="ew")
            
            self.out = scrolledtext.ScrolledText(self, height=18); self.out.grid(row=4, column=0, padx=20, pady=10, sticky="nsew")
            self.grid_rowconfigure(4, weight=1)

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
            algo = self.hash_choice.get()
            export = [k for k, v in self.export_vars.items() if v.get()]
            if not export:
                export = ["sqlite"]
                self.log("    [!] No export format selected -- defaulting to SQLite.\n")
            master_db = os.path.join(out_root, "Arc2Lite_Master_Log.db")
            h_col = f"{algo}_hash TEXT," if algo != "None" else ""
            m_conn = sqlite3.connect(master_db)
            try:
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
                            db = process_archive_logic(p, out_root, file_id, itype, algo, h_val, self.log)
                            if db:
                                apply_export_choice(db, export, self.log)
                            
                            # Apply normalization to the GUI master log entry
                            normalized_gui_log_path = normalize_separators(p)
                            entry = [normalized_gui_log_path, itype]
                            
                            if algo != "None": entry.append(h_val)
                            
                            normalized_gui_db_path = normalize_separators(db)
                            entry.extend([normalized_gui_db_path, datetime.datetime.now(datetime.timezone.utc).isoformat()])
                            
                            m_cursor.execute(f"INSERT INTO processing_log VALUES ({','.join(['?']*len(entry))})", entry)
                            self.log(f"    --- Item Processed ---\n\n")
                            file_id += 1
                m_conn.commit()
            finally:
                # Closed explicitly (see process_archive_logic) since export_tables_to_csv()
                # below opens its own connection to this same master_db file right after.
                m_conn.close()
            apply_export_choice(master_db, export, self.log)
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
        parser.add_argument("-i", "--input", required=True,
                            help="ZIP/TAR/GZ/XZ archive, raw disk image, .E01 acquisition, or a folder of them")
        parser.add_argument("-o", "--output", required=True, help="Path for the export report")
        parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan folder for archives"); parser.add_argument("-ha", "--hash", choices=['md5', 'sha1', 'sha256'], help="Optional hashing options")
        parser.add_argument("-e", "--export", nargs="+", choices=["sqlite", "csv", "timeline"],
                            default=["sqlite"], metavar="{sqlite,csv,timeline}",
                            help="One or more export formats for the results: 'sqlite' (default), "
                                 "'csv', and/or 'timeline' (a Sleuth Kit/mactime bodyfile). Combine "
                                 "as needed, e.g. -e sqlite csv timeline. 'timeline' only ever "
                                 "applies to an archive's or image's own database, never the master log.")
        run_cli(parser.parse_args())
    else:
        if GUI_SUPPORT: app = Arc2LiteGUI(); app.mainloop()
        else: print("GUI libraries not found. Use CLI switches or check requirements.txt for the third-party libraries needed.")
