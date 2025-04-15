import argparse
import csv
import datetime
import os
import sqlite3
import struct
import time
import zipfile
import tarfile

ascii_art = r'''
     _             ____  _     _ _       
    / \   _ __ ___|___ \| |   (_) |_ ___ 
   / _ \ | '__/ __| __) | |   | | __/ _ \
  / ___ \| | | (__ / __/| |___| | ||  __/
 /_/   \_\_|  \___|_____|_____|_|\__\___|
                                                                           
Arc2Lite v0.0.5
https://github.com/stark4n6/Arc2Lite
@KevinPagano3 | @stark4n6 | startme.stark4n6.com
'''

splitter = '\\'
count = 0
files_found = []

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
    created_date = datetime.datetime.fromtimestamp(os.path.getctime(file_path), datetime.timezone.utc)
    modified_date = datetime.datetime.fromtimestamp(os.path.getmtime(file_path), datetime.timezone.utc)
    accessed_date = datetime.datetime.fromtimestamp(os.path.getatime(file_path), datetime.timezone.utc)
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

                # Write file listing
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

    if not os.path.isdir(out_folder):
        print("Output path is not a folder, please run again.")
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
                    # if zipfile.is_zipfile(file_path):
                        # print(f"Found ZIP file: {file_path}")
                        # if process_zip_file(file_path, out_folder, count + 1):
                            # count += 1
                            # files_found.append((file_path, os.path.join(out_folder, f"{count}-{os.path.basename(file_path)}_file_listing.db")))
                    # elif tarfile.is_tarfile(file_path):
                        # print(f"Found TAR file: {file_path}")
                        # if process_tar_file(file_path, out_folder, count + 1):
                            # count += 1
                            # files_found.append((file_path, os.path.join(out_folder, f"{count}-{os.path.basename(file_path)}_file_listing.db")))
                    # else:
                        # process_file(file_path, cursor)
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
        print("Unknown input type, please make sure your input is a folder containing ZIP/TAR files or a single ZIP/TAR file.")

def main(input_path, export_path):
    global count
    global files_found

    print(ascii_art)
    print()

    start_time = time.time()
    print('Start: ' + str(datetime.datetime.now()))
    print('Source: ' + input_path)
    print('Destination: ' + export_path)
    print()

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

    # Check Inputs for Processing
    check_input(input_path, out_folder)

    # Write CSV
    with open(os.path.join(out_folder, "io.csv"), 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(('Input Path', 'Exported File Listing'))
        csv_writer.writerows(files_found)

    print()
    print('****JOB FINISHED****')
    print('Runtime: %s seconds' % (time.time() - start_time))
    #print('ZIP/TAR files processed: ' + str(count))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Arc2Lite v0.0.5 by @KevinPagano3 | @stark4n6 | https://github.com/stark4n6/Arc2Lite")
    parser.add_argument("input_path", help="Path to the ZIP/TAR file or folder for traversing")
    parser.add_argument("export_path", help="Path for the export report")
    #parser.add_argument("embedded extraction", help="Switch to also get file listings of ZIP/TAR files inside a folder")
    args = parser.parse_args()
    main(args.input_path, args.export_path)
