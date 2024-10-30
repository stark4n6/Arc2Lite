import datetime
import zipfile
import struct
import argparse
import os
import sqlite3
import time
import csv

ascii_art = r'''
                 ______    __        __    _ _             
                |__  (_)_ _\ \      / /_ _| | | _____ _ __ 
                  / /| | '_ \ \ /\ / / _` | | |/ / _ \ '__|
                 / /_| | |_) \ V  V / (_| | |   <  __/ |   
                /____|_| .__/ \_/\_/ \__,_|_|_|\_\___|_|   
                       |_|

                           ZipWalker v0.0.2
                  https://github.com/stark4n6/ZipWalker
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
        if header_id == 0x5455:  # Extended Timestamp Extra Field
            flags = struct.unpack_from('B', extra_data, offset)[0]
            offset += 1
            timestamps = {}
            if flags & 1:  # Modification time
                mtime, = struct.unpack_from('<I', extra_data, offset)
                timestamps['mtime'] = datetime.datetime.fromtimestamp(mtime, datetime.timezone.utc)
                offset += 4
            if flags & 2:  # Access time
                atime, = struct.unpack_from('<I', extra_data, offset)
                timestamps['atime'] = datetime.datetime.fromtimestamp(atime, datetime.timezone.utc)
                offset += 4
            if flags & 4:  # Creation time
                ctime, = struct.unpack_from('<I', extra_data, offset)
                timestamps['ctime'] = datetime.datetime.fromtimestamp(ctime, datetime.timezone.utc)
                offset += 4
            return timestamps
        else:
            offset += data_size
    return None
    
def check_input(input_path,out_folder):
    global count
    global files_found
    
    if os.path.isdir(out_folder):
        if os.path.isdir(input_path):
            for root, dirs, files in os.walk(input_path):
                for file in files:
                    if file.endswith(".zip"):
                        zip_file_path = os.path.join(root, file)
                        print(f"Found ZIP file: {zip_file_path}")
                        print()
                        process_input(zip_file_path,out_folder)
                        count += 1
                        files_found.append((zip_file_path,str(count) + '-' + os.path.basename(zip_file_path) + '_file_listing.db'))
        
        elif zipfile.is_zipfile(input_path):
            print(f"Processing ZIP file: {input_path}")
            process_input(input_path,out_folder)
            files_found.append((input_path,os.path.basename(input_path) + '_file_listing.db'))
        else:
            print("Unknown input type, please make sure your input contains ZIP files.")
    else:
        print("Output path is not a folder, please run again.")
    
def process_input(input_path,out_folder):
    global count
    try:
        db_file_path = out_folder + splitter + str(count) + '-' + os.path.basename(input_path) + '_file_listing.db'
        with zipfile.ZipFile(input_path, mode="r") as archive, sqlite3.connect(db_file_path) as conn:
            
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

                #print(f"Modified: {datetime.datetime(*info.date_time)}")
                
                timestamps = decode_extended_timestamp(info.extra)
                if timestamps and 'ctime' in timestamps:
                    created_date = timestamps['ctime']
                else:
                    created_date = ''
                if timestamps and 'atime' in timestamps:
                    accessed_date = timestamps['atime']
                else:
                    accessed_date = ''
                if timestamps and 'mtime' in timestamps:
                    modified_date = timestamps['mtime']
                else:
                    modified_date = ''
                
                is_file = 1 if not entry_path.endswith('/') else 0  # Check if it's a file
                file_name = os.path.basename(entry_path) if is_file else None
                file_extension = os.path.splitext(file_name)[1] if is_file else None
                
                cursor.execute("INSERT OR IGNORE INTO file_listing (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (file_name, file_extension, entry_path, created_date, modified_date, accessed_date, is_file, size, comp_size))

        conn.commit()

    except FileNotFoundError:
        print(f"ZIP file '{input_path}' not found.")
        
def main(input_path,export_path):
    global count
    global files_found
    
    print(ascii_art)
    print()
    
    start_time = time.time()
    print('Start: ' + str(datetime.datetime.now()))
    print('Source: ' + input_path)
    print('Destination: ' + export_path)
    print()
    
    base = "ZipWalker_Out_"
    
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
    out_folder = export_path + base + output_ts
    os.makedirs(out_folder)
    
    # Check Inputs for Processing
    check_input(input_path,out_folder)
    
    # Write CSV
    with open(out_folder + splitter + "Zips.csv", 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(('Input Path','Exported File Listing'))
        csv_writer.writerows(files_found)
        
    print()
    print('****JOB FINISHED****')
    print('Runtime: %s seconds' % (time.time() - start_time))
    print('ZIP files processed: ' + str(count))
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZipWalker v0.0.2 by @KevinPagano3 | @stark4n6 | https://github.com/stark4n6/ZipWalker")
    parser.add_argument("input_path", help="Path to the ZIP file or folder containing ZIP files")
    parser.add_argument("export_path", help="Path for the export report")
    args = parser.parse_args()
    main(args.input_path,args.export_path)