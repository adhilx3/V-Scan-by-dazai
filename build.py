"""
Builds "V-Scan by dazai.exe" with YOUR VirusTotal API key baked in,
so the finished app never asks for a key.

Usage:  python build.py
"""
import getpass
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "vscan.py")
TMP_DIR = os.path.join(HERE, "_build_tmp")
TMP_SRC = os.path.join(TMP_DIR, "vscan_build.py")
EXE_NAME = "V-Scan by dazai"
PLACEHOLDER = '"__VT_API_KEY__"'


def main():
    key = getpass.getpass("Enter your VirusTotal API key (input is hidden): ").strip()
    if not key:
        sys.exit("No key entered. Aborting.")
    if len(key) != 64:
        print("Warning: VirusTotal keys are normally 64 characters. Double-check yours.")
        if input("Continue anyway? (y/n): ").strip().lower() != "y":
            sys.exit("Aborted.")

    with open(SOURCE, "r", encoding="utf-8") as f:
        code = f.read()
    if PLACEHOLDER not in code:
        sys.exit("Placeholder not found in vscan.py. Use the original file.")

    os.makedirs(TMP_DIR, exist_ok=True)
    with open(TMP_SRC, "w", encoding="utf-8") as f:
        f.write(code.replace(PLACEHOLDER, json.dumps(key)))

    try:
        print("Installing requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade",
                               "requests", "customtkinter", "pyinstaller"])
        print("Building exe...")
        subprocess.check_call([
            sys.executable, "-m", "PyInstaller", "--onefile", "--windowed", "--clean",
            "--name", EXE_NAME, "--collect-all", "customtkinter",
            "--distpath", os.path.join(HERE, "dist"),
            "--workpath", os.path.join(TMP_DIR, "work"),
            "--specpath", TMP_DIR, TMP_SRC,
        ])
    finally:
        # remove every temp file that contains the key
        shutil.rmtree(TMP_DIR, ignore_errors=True)

    print(f"\nDone! Your app is at: {os.path.join(HERE, 'dist', EXE_NAME + '.exe')}")


if __name__ == "__main__":
    main()
