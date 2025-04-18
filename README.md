# Arc2Lite

<p align="center">
<img src="https://github.com/stark4n6/Arc2Lite/blob/main/assets/Arc2Lite.png" width="300" height="300">
</p>
A simple script to read the contents of a zip/tar/gz archive and extract metadata to a SQLite DB.

## UPDATE 2025-04-18:
GUI added, mostly thanks to Gemini!
<p align="center">
<img src="https://github.com/user-attachments/assets/1df34425-1c4a-463f-8328-137f122df687">
</p>

## UPDATE 2025-04-15:
Because making original names is hard, this is the final form, Arc2Lite.

## UPDATE 2025-04-14: 
With v0.0.4 this now handles ZIP and TAR and folder paths, so the script has been renamed to FileWalker (how original).

## Command Line Switches
```
usage: Arc2Lite.py [-h] input_path export_path

Arc2Lite v0.0.6 by @KevinPagano3 | @stark4n6 | https://github.com/stark4n6/Arc2Lite

positional arguments:
  input_path   Path to the ZIP/TAR file or folder for traversing
  export_path  Path for the export report

options:
  -h, --help   show this help message and exit
```
