import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, Menu
from PIL import Image, ImageTk  # For image handling
import argparse
import csv
import datetime
import os
import sqlite3
import struct
import time
import zipfile
import tarfile
import threading
import subprocess  # For opening the file explorer

IMAGE_FILENAME = "./assets/Arc2Lite.png"
IMAGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), IMAGE_FILENAME)

splitter = '\\'
count = 0
files_found = []
output_folder_path = None

def is_platform_windows():
    '''Returns True if running on Windows'''
    return os.name == 'nt'

def decode_extended_timestamp(extra_data):
    offset = 0
    length = len(extra_data)
    while offset < length:
        header_id, data_size = struct.unpack_from('<HH', extra_data, offset)
        offset += 4
        if header_id == 0x5455: # Extended Timestamp Extra Field
            flags = struct.unpack_from('B', extra_data, offset)[0]
            offset += 1
            timestamps = {}
            if flags & 1: # Modification time
                mtime, = struct.unpack_from('<I', extra_data, offset)
                timestamps['mtime'] = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc)
                offset += 4
            if flags & 2: # Access time
                atime, = struct.unpack_from('<I', extra_data, offset)
                timestamps['atime'] = datetime.datetime.fromtimestamp(atime, datetime.timezone.utc)
                offset += 4
            if flags & 4: # Creation time
                ctime, = struct.unpack_from('<I', extra_data, offset)
                timestamps['ctime'] = datetime.datetime.fromtimestamp(ctime, datetime.timezone.utc)
                offset += 4
            return timestamps
        else:
            offset += data_size
    return None

def process_file(file_path, db_cursor):
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1]
    entry_path = file_path.replace('\\', '/') # Standardize path for DB
    try:
        created_date = datetime.datetime.fromtimestamp(os.path.getctime(file_path), datetime.timezone.utc)
        modified_date = datetime.datetime.fromtimestamp(os.path.getmtime(file_path), datetime.timezone.utc)
        accessed_date = datetime.datetime.fromtimestamp(os.path.getatime(file_path), datetime.timezone.utc)
    except OSError:
        created_date = None
        modified_date = None
        accessed_date = None
    is_file = 1
    size = os.path.getsize(file_path)
    comp_size = None # Not applicable to regular files

    db_cursor.execute("INSERT OR IGNORE INTO file_listing (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size))

def process_zip_file(zip_file_path, out_folder, count):
    try:
        db_file_path = os.path.join(out_folder, f"{count}-{os.path.basename(zip_file_path)}_file_listing.db")
        with zipfile.ZipFile(zip_file_path, mode="r") as archive, sqlite3.connect(db_file_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_listing (
                    file_name TEXT,
                    file_extension TEXT,
                    entry_path TEXT COLLATE NOCASE PRIMARY KEY,
                    created_date TEXT,
                    modified_date TEXT,
                    accessed_date TEXT,
                    is_file INTEGER,
                    size INTEGER,
                    comp_size INTEGER
                )
            ''')

            for info in archive.infolist():
                entry_path = info.filename
                size = info.file_size
                comp_size = info.compress_size

                timestamps = decode_extended_timestamp(info.extra)
                created_date = timestamps.get('ctime', '') if timestamps else ''
                accessed_date = timestamps.get('atime', '') if timestamps else ''
                modified_date = timestamps.get('mtime', datetime.datetime(*info.date_time, tzinfo=datetime.timezone.utc)) if timestamps else ''

                is_file = 1 if not entry_path.endswith('/') else 0 # Check if it's a file
                file_name = os.path.basename(entry_path) if is_file else None
                file_extension = os.path.splitext(file_name)[1] if is_file and file_name else None

                # Write file listing
                cursor.execute("INSERT OR IGNORE INTO file_listing (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size))

            conn.commit()
            return True
    except FileNotFoundError:
        print(f"ZIP file '{zip_file_path}' not found.")
        return False
    except zipfile.BadZipFile:
        print(f"'{zip_file_path}' is not a valid ZIP file.")
        return False

def process_tar_file(tar_file_path, out_folder, count):
    try:
        db_file_path = os.path.join(out_folder, f"{count}-{os.path.basename(tar_file_path)}_file_listing.db")
        with tarfile.open(tar_file_path, mode="r:*") as archive, sqlite3.connect(db_file_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_listing (
                    file_name TEXT,
                    file_extension TEXT,
                    entry_path TEXT COLLATE NOCASE PRIMARY KEY,
                    created_date TEXT,
                    modified_date TEXT,
                    accessed_date TEXT,
                    is_file INTEGER,
                    size INTEGER,
                    comp_size INTEGER
                )
            ''')

            for member in archive.getmembers():
                entry_path = member.name
                size = member.size
                # tar files don't inherently have a compressed size accessible this way
                comp_size = None

                created_date = datetime.datetime.fromtimestamp(member.mtime, datetime.timezone.utc) if member.mtime else ''
                modified_date = datetime.datetime.fromtimestamp(member.mtime, datetime.timezone.utc) if member.mtime else ''
                # Access time might not be readily available in tar archives
                accessed_date = ''

                is_file = 1 if member.isfile() else 0
                file_name = os.path.basename(entry_path) if is_file else None
                file_extension = os.path.splitext(file_name)[1] if is_file and file_name else None

                cursor.execute("INSERT OR IGNORE INTO file_listing (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size))

            conn.commit()
            return True
    except FileNotFoundError:
        print(f"TAR file '{tar_file_path}' not found.")
        return False
    except tarfile.ReadError:
        print(f"'{tar_file_path}' is not a valid TAR file.")
        return False

def check_input(input_path, out_folder):
    global count
    global files_found
    global output_folder_path
    output_folder_path = out_folder

    if not os.path.isdir(out_folder):
        messagebox.showerror("Error", "Output path is not a folder, please select a valid output folder.")
        return

    if os.path.isdir(input_path):
        db_file_path = os.path.join(out_folder, f"folder_listing_{os.path.basename(input_path)}.db")
        with sqlite3.connect(db_file_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_listing (
                    file_name TEXT,
                    file_extension TEXT,
                    entry_path TEXT COLLATE NOCASE PRIMARY KEY,
                    created_date TEXT,
                    modified_date TEXT,
                    accessed_date TEXT,
                    is_file INTEGER,
                    size INTEGER,
                    comp_size INTEGER
                )
            ''')
            for root, _, files in os.walk(input_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    process_file(file_path, cursor)
            conn.commit()
            files_found.append((input_path, db_file_path))
            count = 1 # Reset count as we are listing the folder itself

    # Process if just a zip or tar file for input
    elif zipfile.is_zipfile(input_path):
        print(f"Processing ZIP file: {input_path}")
        if process_zip_file(input_path, out_folder, 1):
            files_found.append((input_path, os.path.join(out_folder, f"1-{os.path.basename(input_path)}_file_listing.db")))
            count = 1
    elif tarfile.is_tarfile(input_path):
        print(f"Processing TAR file: {input_path}")
        if process_tar_file(input_path, out_folder, 1):
            files_found.append((input_path, os.path.join(out_folder, f"1-{os.path.basename(input_path)}_file_listing.db")))
            count = 1
    else:
        messagebox.showerror("Error", "Unknown input type, please make sure your input is a folder containing ZIP/TAR files or a single ZIP/TAR file.")

class Arc2LiteGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Arc2Lite v0.0.6")
        self.after(250, lambda: self.iconbitmap("./assets/stark4n6.ico"))
        self.geometry("800x625")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0) # Image row
        self.grid_rowconfigure(2, weight=0) # ASCII art row
        self.grid_rowconfigure(3, weight=0) # Input path row
        self.grid_rowconfigure(4, weight=0) # Export path row
        self.grid_rowconfigure(5, weight=0) # Start button row
        self.grid_rowconfigure(6, weight=1) # Output text row

        self.input_path = tk.StringVar()
        self.export_path = tk.StringVar()
        self.image_label = None # To hold the image label

        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        menubar = Menu(self)
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Close", command=self.close_program)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def show_about(self):
        messagebox.showinfo("About Arc2Lite", "Arc2Lite v0.0.6\nhttps://github.com/stark4n6/Arc2Lite\nCreated by @KevinPagano3 | @stark4n6")

    def close_program(self):
        self.destroy()

    def create_widgets(self):
        # Image Placeholder
        if os.path.exists(IMAGE_PATH):
            try:
                img = Image.open(IMAGE_PATH)
                img = img.resize((250, 250))
                self.image_tk = ImageTk.PhotoImage(img)
                self.image_label = ctk.CTkLabel(self, image=self.image_tk, text="")
                self.image_label.grid(row=1, column=0, padx=20, pady=(20, 5), sticky="n")
            except Exception as e:
                print(f"Error loading image: {e}")
                self.image_label = ctk.CTkLabel(self, text="[Image Placeholder]", font=ctk.CTkFont(size=16, weight="bold"))
                self.image_label.grid(row=1, column=0, padx=20, pady=(20, 5), sticky="n")
        else:
            self.image_label = ctk.CTkLabel(self, text="[Image Placeholder]", font=ctk.CTkFont(size=16, weight="bold"))
            self.image_label.grid(row=1, column=0, padx=20, pady=(20, 5), sticky="n")

        # Input Path
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="ew")
        self.input_label = ctk.CTkLabel(self.input_frame, text="Input Path:")
        self.input_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.input_entry = ctk.CTkEntry(self.input_frame, textvariable=self.input_path)
        self.input_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.input_button = ctk.CTkButton(self.input_frame, text="Browse", command=self.browse_input)
        self.input_button.grid(row=0, column=2, padx=10, pady=5, sticky="e")
        self.input_frame.grid_columnconfigure(1, weight=1)

        # Export Path
        self.export_frame = ctk.CTkFrame(self)
        self.export_frame.grid(row=4, column=0, padx=20, pady=(5, 10), sticky="ew")
        self.export_label = ctk.CTkLabel(self.export_frame, text="Export Path:")
        self.export_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.export_entry = ctk.CTkEntry(self.export_frame, textvariable=self.export_path)
        self.export_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.export_button = ctk.CTkButton(self.export_frame, text="Browse", command=self.browse_export)
        self.export_button.grid(row=0, column=2, padx=10, pady=5, sticky="e")
        self.export_frame.grid_columnconfigure(1, weight=1)

        # Start Button
        self.start_button = ctk.CTkButton(self, text="Start Processing", command=self.start_processing_threaded)
        self.start_button.grid(row=5, column=0, padx=20, pady=(10, 20), sticky="ew")

        # Output Text (using scrolledtext)
        self.output_text = scrolledtext.ScrolledText(self, height=10, wrap=tk.WORD)
        self.output_text.grid(row=6, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.grid_rowconfigure(6, weight=1)
        self.output_text.insert("1.0", "Ready to start processing...\n")
        self.output_text.config(state=tk.DISABLED)

    def browse_input(self):
        file_or_folder = filedialog.askopenfilename()
        if file_or_folder:
            self.input_path.set(file_or_folder)

    def browse_export(self):
        folder = filedialog.askdirectory()
        if folder:
            self.export_path.set(folder)

    def start_processing_threaded(self):
        input_path = self.input_path.get()
        export_path = self.export_path.get()

        if not input_path or not export_path:
            messagebox.showerror("Error", "Please select both input and export paths.")
            return

        self.start_button.configure(state="disabled", text="Processing...")
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", f"Start: {datetime.datetime.now()}\nSource: {input_path}\nDestination: {export_path}\n\n")
        self.output_text.config(state=tk.DISABLED)

        self.processing_thread = threading.Thread(target=self.process_data, args=(input_path, export_path))
        self.processing_thread.start()

    def process_data(self, input_path, export_path):
        global files_found
        files_found = []
        global count
        count = 0
        global output_folder_path

        base = "Arc2Lite_Out_"
        if is_platform_windows():
            if input_path[1] == ':': input_path = '\\\\?\\' + input_path.replace('/', '\\')
            if export_path[1] == ':': export_path = '\\\\?\\' + export_path.replace('/', '\\')

            if not export_path.endswith('\\'):
                export_path = export_path + '\\'

        platform = is_platform_windows()
        if platform:
            splitter = '\\'
        else:
            splitter = '/'

        output_ts = time.strftime("%Y%m%d-%H%M%S")
        out_folder = os.path.join(export_path, base + output_ts)
        os.makedirs(out_folder, exist_ok=True)
        output_folder_path = out_folder

        # Check Inputs for Processing
        check_input(input_path, out_folder)

        # Write CSV
        with open(os.path.join(out_folder, "io.csv"), 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(('Input Path', 'Exported File Listing'))
            csv_writer.writerows(files_found)

        self.update_gui_after_processing()

    def update_gui_after_processing(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.tag_configure("finished", background="cyan")
        self.output_text.insert(tk.END, "****JOB FINISHED****\n", "finished")
        self.output_text.insert(tk.END, f"Runtime: {time.time() - self.start_time:.2f} seconds\n")
        self.output_text.config(state=tk.DISABLED)
        self.start_button.configure(state="normal", text="Start Processing")
        self.show_completion_popup()

    def show_completion_popup(self):
        global output_folder_path
        if output_folder_path:
            open_folder = messagebox.askyesno("Processing Complete", "Finished processing. Do you want to open the output folder?")
            if open_folder:
                if is_platform_windows():
                    os.startfile(output_folder_path)
                else:
                    subprocess.Popen(['xdg-open', output_folder_path])

    def main_gui(self):
        self.start_time = time.time()
        self.mainloop()

if __name__ == "__main__":
    app = Arc2LiteGUI()
    app.main_gui()