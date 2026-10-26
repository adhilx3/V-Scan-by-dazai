"""
V-Scan by dazai - file & URL scanner powered by VirusTotal.

Run from source:   python vscan.py
Build the .exe:    python build.py   (asks for your API key and bakes it in)
"""
import base64
import hashlib
import json
import os
import threading
import time
import webbrowser
from tkinter import filedialog

import customtkinter as ctk
import requests

APP_NAME = "V-Scan"
AUTHOR = "dazai"

# build.py replaces this placeholder with your real key before packaging.
EMBEDDED_API_KEY = "__VT_API_KEY__"

API = "https://www.virustotal.com/api/v3"
CONFIG = os.path.join(os.path.expanduser("~"), ".vscan.json")
SMALL_LIMIT = 32 * 1024 * 1024
MAX_LIMIT = 650 * 1024 * 1024

# ---------- palette ----------
BG = "#0d0f16"
CARD = "#161a25"
CARD2 = "#1d2230"
BORDER = "#2a3042"
TEXT = "#e8eaf0"
MUTED = "#8b93a7"
ACCENT = "#7c5cff"
ACCENT_H = "#6a49f0"
GREEN = "#22c55e"
AMBER = "#f59e0b"
RED = "#ef4444"

LEVELS = {
    "clean": ("CLEAN", "No engine flagged this. Looks safe.", GREEN),
    "warn": ("SUSPICIOUS", "Could be a false positive. Be careful.", AMBER),
    "danger": ("DANGEROUS", "Likely malicious. Do not open it.", RED),
}


# ---------- key handling ----------
def embedded_key():
    return "" if EMBEDDED_API_KEY.startswith("__") else EMBEDDED_API_KEY


def load_saved_key():
    try:
        with open(CONFIG, "r", encoding="utf-8") as f:
            return json.load(f).get("api_key", "")
    except Exception:
        return os.environ.get("VT_API_KEY", "")


def save_key(key):
    try:
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump({"api_key": key}, f)
    except Exception:
        pass


# ---------- VirusTotal logic ----------
class VTError(Exception):
    pass


def vt_request(method, url, key, **kwargs):
    headers = {"x-apikey": key, "accept": "application/json"}
    try:
        r = requests.request(method, url, headers=headers, timeout=60, **kwargs)
    except requests.RequestException as e:
        raise VTError(f"Network error: {e}")
    if r.status_code == 401:
        raise VTError("Invalid API key.")
    if r.status_code == 429:
        raise VTError("Rate limit hit (free tier: 4 requests/min, 500/day). Wait a minute and retry.")
    return r


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_for_analysis(analysis_id, key, status):
    for i in range(18):
        r = vt_request("GET", f"{API}/analyses/{analysis_id}", key)
        if r.status_code == 200:
            if r.json()["data"]["attributes"]["status"] == "completed":
                return
        status(f"Analysis in progress... ({i + 1})")
        time.sleep(10)
    raise VTError("Analysis timed out. Try again in a moment.")


def build_result(attrs, link, title):
    stats = attrs.get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    if mal >= 5:
        level = "danger"
    elif mal > 0 or sus > 0:
        level = "warn"
    else:
        level = "clean"
    flagged = [
        (eng, res.get("result") or res.get("category"))
        for eng, res in attrs.get("last_analysis_results", {}).items()
        if res.get("category") in ("malicious", "suspicious")
    ]
    return {
        "kind": "result", "level": level, "title": title, "link": link,
        "stats": stats, "total": total, "flagged": flagged,
    }


def scan_file(path, key, allow_upload, status):
    size = os.path.getsize(path)
    name = os.path.basename(path)
    status("Hashing file...")
    digest = sha256_file(path)
    link = f"https://www.virustotal.com/gui/file/{digest}"
    title = f"{name}\nSHA-256: {digest}"

    status("Looking up VirusTotal database...")
    r = vt_request("GET", f"{API}/files/{digest}", key)
    if r.status_code == 200:
        return build_result(r.json()["data"]["attributes"], link, title)
    if r.status_code != 404:
        raise VTError(f"Unexpected response: {r.status_code}")

    if not allow_upload:
        return {"kind": "message", "text": "This file is unknown to VirusTotal.\n"
                "Tick \"Upload unknown files\" and scan again to analyze it."}
    if size > MAX_LIMIT:
        return {"kind": "message", "text": "File is larger than 650 MB, which VirusTotal can't accept."}

    status("Uploading file to VirusTotal...")
    upload_url = f"{API}/files"
    if size > SMALL_LIMIT:
        upload_url = vt_request("GET", f"{API}/files/upload_url", key).json()["data"]
    with open(path, "rb") as f:
        r = vt_request("POST", upload_url, key, files={"file": (name, f)})
    if r.status_code != 200:
        raise VTError(f"Upload failed: {r.status_code}")

    wait_for_analysis(r.json()["data"]["id"], key, status)
    r = vt_request("GET", f"{API}/files/{digest}", key)
    if r.status_code != 200:
        raise VTError("Could not fetch the final report.")
    return build_result(r.json()["data"]["attributes"], link, title)


def scan_url(url, key, status):
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    link = f"https://www.virustotal.com/gui/url/{url_id}"

    status("Checking URL reputation...")
    r = vt_request("GET", f"{API}/urls/{url_id}", key)
    if r.status_code == 404:
        status("Submitting URL for analysis...")
        s = vt_request("POST", f"{API}/urls", key, data={"url": url})
        if s.status_code != 200:
            raise VTError(f"Submit failed: {s.status_code}")
        wait_for_analysis(s.json()["data"]["id"], key, status)
        r = vt_request("GET", f"{API}/urls/{url_id}", key)
    if r.status_code != 200:
        raise VTError(f"Unexpected response: {r.status_code}")
    return build_result(r.json()["data"]["attributes"], link, url)


# ---------- GUI ----------
class VScan(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title(f"{APP_NAME} by {AUTHOR}")
        self.geometry("760x820")
        self.minsize(680, 720)
        self.configure(fg_color=BG)

        self.key = embedded_key() or load_saved_key()
        self.busy = False
        self.report_link = ""

        self.build_header()
        self.build_tabs()
        self.build_status()
        self.build_result_card()

    # ----- layout -----
    def build_header(self):
        head = ctk.CTkFrame(self, fg_color=CARD, corner_radius=16)
        head.pack(fill="x", padx=18, pady=(18, 10))

        shield = ctk.CTkLabel(head, text="🛡", font=("Segoe UI Emoji", 38), text_color=ACCENT)
        shield.pack(side="left", padx=(18, 8), pady=12)

        titles = ctk.CTkFrame(head, fg_color="transparent")
        titles.pack(side="left", pady=12)
        ctk.CTkLabel(titles, text=APP_NAME.upper(), font=("Segoe UI", 28, "bold"),
                     text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(titles, text=f"by {AUTHOR}  •  powered by VirusTotal",
                     font=("Segoe UI", 12), text_color=MUTED).pack(anchor="w")

        if not embedded_key():
            ctk.CTkButton(head, text="⚙  API key", width=100, height=32, fg_color=CARD2,
                          hover_color=BORDER, text_color=TEXT,
                          command=self.ask_key).pack(side="right", padx=18)

    def build_tabs(self):
        self.tabs = ctk.CTkTabview(
            self, fg_color=CARD, corner_radius=16, height=190,
            segmented_button_fg_color=CARD2, segmented_button_selected_color=ACCENT,
            segmented_button_selected_hover_color=ACCENT_H,
            segmented_button_unselected_color=CARD2,
            segmented_button_unselected_hover_color=BORDER, text_color=TEXT)
        self.tabs.pack(fill="x", padx=18, pady=6)
        file_tab = self.tabs.add("📄  Scan File")
        url_tab = self.tabs.add("🌐  Scan URL")

        # file tab
        self.file_label = ctk.CTkLabel(file_tab, text="No file selected", text_color=MUTED,
                                       font=("Segoe UI", 12))
        self.file_label.pack(pady=(14, 6))
        self.file_btn = ctk.CTkButton(file_tab, text="Choose file and scan", height=42, width=240,
                                      font=("Segoe UI", 14, "bold"), corner_radius=10,
                                      fg_color=ACCENT, hover_color=ACCENT_H, command=self.on_file)
        self.file_btn.pack(pady=4)
        self.upload_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(file_tab, text="Upload unknown files (visible to VirusTotal community)",
                        variable=self.upload_var, text_color=MUTED, fg_color=ACCENT,
                        hover_color=ACCENT_H, font=("Segoe UI", 12)).pack(pady=8)

        # url tab
        ctk.CTkLabel(url_tab, text="Paste a link to check before you open it", text_color=MUTED,
                     font=("Segoe UI", 12)).pack(pady=(14, 6))
        row = ctk.CTkFrame(url_tab, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=4)
        self.url_entry = ctk.CTkEntry(row, placeholder_text="https://example.com", height=42,
                                      fg_color=CARD2, border_color=BORDER, text_color=TEXT,
                                      font=("Segoe UI", 13))
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.url_entry.bind("<Return>", lambda e: self.on_url())
        self.url_btn = ctk.CTkButton(row, text="Scan URL", height=42, width=120,
                                     font=("Segoe UI", 14, "bold"), corner_radius=10,
                                     fg_color=ACCENT, hover_color=ACCENT_H, command=self.on_url)
        self.url_btn.pack(side="left")

    def build_status(self):
        self.status_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.status_frame.pack(fill="x", padx=18, pady=(8, 0))
        self.status = ctk.CTkLabel(self.status_frame, text="Ready", text_color=MUTED,
                                   font=("Segoe UI", 12), wraplength=680, justify="center")
        self.status.pack()
        self.progress = ctk.CTkProgressBar(self.status_frame, mode="indeterminate",
                                           progress_color=ACCENT, fg_color=CARD2, height=6)

    def build_result_card(self):
        self.card = ctk.CTkFrame(self, fg_color=CARD, corner_radius=16)

        top = ctk.CTkFrame(self.card, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(16, 6))

        self.gauge = ctk.CTkCanvas(top, width=150, height=150, bg=CARD, highlightthickness=0)
        self.gauge.pack(side="left", padx=(4, 16))

        right = ctk.CTkFrame(top, fg_color="transparent")
        right.pack(side="left", fill="both", expand=True)
        self.badge = ctk.CTkLabel(right, text="", font=("Segoe UI", 22, "bold"),
                                  corner_radius=10, width=200, height=40, text_color="#0d0f16")
        self.badge.pack(anchor="w")
        self.verdict_text = ctk.CTkLabel(right, text="", text_color=MUTED, font=("Segoe UI", 12),
                                         wraplength=420, justify="left")
        self.verdict_text.pack(anchor="w", pady=(6, 2))
        self.target_text = ctk.CTkLabel(right, text="", text_color=TEXT, font=("Segoe UI", 11),
                                        wraplength=420, justify="left")
        self.target_text.pack(anchor="w")

        self.chips = ctk.CTkFrame(self.card, fg_color="transparent")
        self.chips.pack(fill="x", padx=16, pady=6)
        self.chip_labels = {}
        for key, caption, color in (("malicious", "Malicious", RED), ("suspicious", "Suspicious", AMBER),
                                    ("harmless", "Harmless", GREEN), ("undetected", "Undetected", MUTED)):
            chip = ctk.CTkFrame(self.chips, fg_color=CARD2, corner_radius=10)
            chip.pack(side="left", expand=True, fill="x", padx=4)
            num = ctk.CTkLabel(chip, text="0", font=("Segoe UI", 22, "bold"), text_color=color)
            num.pack(pady=(8, 0))
            ctk.CTkLabel(chip, text=caption, font=("Segoe UI", 11), text_color=MUTED).pack(pady=(0, 8))
            self.chip_labels[key] = num

        ctk.CTkLabel(self.card, text="Detections", font=("Segoe UI", 12, "bold"),
                     text_color=TEXT).pack(anchor="w", padx=20, pady=(8, 2))
        self.flag_box = ctk.CTkTextbox(self.card, height=120, fg_color=CARD2, text_color=TEXT,
                                       font=("Consolas", 12), corner_radius=10)
        self.flag_box.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        ctk.CTkButton(self.card, text="Open full VirusTotal report  ↗", height=38,
                      fg_color=CARD2, hover_color=BORDER, text_color=TEXT,
                      command=lambda: webbrowser.open(self.report_link)).pack(pady=(0, 14))

    # ----- helpers -----
    def set_status(self, text, color=MUTED):
        self.after(0, lambda: self.status.configure(text=text, text_color=color))

    def get_key(self):
        if not self.key:
            self.ask_key()
        return self.key

    def ask_key(self):
        dlg = ctk.CTkInputDialog(text="Paste your VirusTotal API key:", title="API key")
        value = (dlg.get_input() or "").strip()
        if value:
            self.key = value
            save_key(value)

    def draw_gauge(self, flagged, total, color):
        c = self.gauge
        c.delete("all")
        box = (14, 14, 136, 136)
        c.create_arc(*box, start=90, extent=359.9, style="arc", outline=BORDER, width=12)
        if flagged == 0:
            c.create_arc(*box, start=90, extent=359.9, style="arc", outline=color, width=12)
        else:
            extent = -max(10.0, 359.9 * flagged / total)
            c.create_arc(*box, start=90, extent=extent, style="arc", outline=color, width=12)
        c.create_text(75, 68, text=str(flagged), fill=TEXT, font=("Segoe UI", 30, "bold"))
        c.create_text(75, 100, text=f"of {total} engines", fill=MUTED, font=("Segoe UI", 9))

    def set_busy(self, busy):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.file_btn.configure(state=state)
        self.url_btn.configure(state=state)
        if busy:
            self.card.pack_forget()
            self.progress.pack(fill="x", pady=(8, 0))
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.pack_forget()

    def run_scan(self, fn, *args):
        if self.busy:
            return
        self.set_busy(True)
        self.set_status("Starting scan...")

        def worker():
            try:
                res = fn(*args, self.set_status)
                self.after(0, self.show_result, res)
            except VTError as e:
                self.after(0, self.show_error, str(e))
            except Exception as e:
                self.after(0, self.show_error, f"Unexpected error: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def show_error(self, text):
        self.set_busy(False)
        self.set_status(f"⚠  {text}", RED)

    def show_result(self, res):
        self.set_busy(False)
        if res["kind"] == "message":
            self.set_status(res["text"], AMBER)
            return

        label, desc, color = LEVELS[res["level"]]
        stats = res["stats"]
        flagged_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
        self.report_link = res["link"]

        self.draw_gauge(flagged_count, res["total"], color)
        self.badge.configure(text=label, fg_color=color)
        self.verdict_text.configure(text=desc)
        self.target_text.configure(text=res["title"])
        for k, lbl in self.chip_labels.items():
            lbl.configure(text=str(stats.get(k, 0)))

        self.flag_box.configure(state="normal")
        self.flag_box.delete("1.0", "end")
        if res["flagged"]:
            for eng, verdict in res["flagged"]:
                self.flag_box.insert("end", f"•  {eng}:  {verdict}\n")
        else:
            self.flag_box.insert("end", "No threats reported by any engine.")
        self.flag_box.configure(state="disabled")

        self.set_status("Scan complete", GREEN)
        self.card.pack(fill="both", expand=True, padx=18, pady=(10, 18))

    # ----- actions -----
    def on_file(self):
        key = self.get_key()
        if not key:
            return
        path = filedialog.askopenfilename(title="Choose a file to scan")
        if not path:
            return
        self.file_label.configure(text=os.path.basename(path), text_color=TEXT)
        self.run_scan(scan_file, path, key, self.upload_var.get())

    def on_url(self):
        key = self.get_key()
        url = self.url_entry.get().strip()
        if not key or not url:
            return
        self.run_scan(scan_url, url, key)


if __name__ == "__main__":
    VScan().mainloop()
