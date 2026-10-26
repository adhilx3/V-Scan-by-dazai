<div align="center">

# 🛡️ V-Scan

**A sleek Windows desktop app that scans files and URLs with VirusTotal, built by dazai.**

![Python](https://img.shields.io/badge/Python-3.9%2B-7c5cff?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-22c55e?style=for-the-badge&logo=windows&logoColor=white)
![Powered by](https://img.shields.io/badge/Powered%20by-VirusTotal-3b82f6?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)

<img src="assets/screenshot.png" alt="V-Scan screenshot" width="640">

</div>

---

## ✨ Features

- 📄 **File scanning**: checks a file's SHA-256 hash against VirusTotal's database of 70+ antivirus engines. Nothing is uploaded unless you choose to.
- 🌐 **URL scanning**: check a link's reputation before you click it.
- 📤 **Optional upload**: scan files VirusTotal has never seen (up to 650 MB).
- 🎯 **Clear verdicts**: a color-coded badge (Clean, Suspicious or Dangerous) with a circular detection gauge.
- 📊 **Detailed breakdown**: counts for malicious, suspicious, harmless and undetected, plus the exact engines that flagged the item.
- 🔗 **One-click full report**: open the complete VirusTotal page in your browser.
- 🌙 **Modern dark UI**: built with CustomTkinter.
- ⚡ **Non-blocking**: scans run in the background, so the window never freezes.

---

## 📥 Download

Grab the latest `V-Scan by dazai.exe` from the [**Releases**](../../releases) page. No Python needed, just Windows and an internet connection.

On first launch you'll be asked for your free VirusTotal API key. It's saved locally, so you only enter it once.

> **Windows SmartScreen** may show an "unknown publisher" warning because the app isn't code-signed. Click **More info → Run anyway**. You can also review the source code here or build the app yourself.

---

## 🔑 Getting a VirusTotal API key

1. Create a free account at [virustotal.com](https://www.virustotal.com/gui/join-us).
2. Click your profile icon → **API key**.
3. Copy the key and paste it into V-Scan.

**Free tier limits:** 4 requests per minute, 500 per day.

---

## 🚀 Run from source

```bash
git clone https://github.com/YOUR_USERNAME/V-Scan.git
cd V-Scan
pip install requests customtkinter
python vscan.py
```

---

## 🛠️ Build your own .exe

### Option 1: Personal build (your API key baked in)

The app will never ask for a key. **Keep this exe for yourself.**

```bash
python build.py
```

Paste your key when prompted (input is hidden). The script bakes it into a temporary copy of the code, builds the app, then deletes the temporary copy. Your original `vscan.py` is never modified. The result is `dist/V-Scan by dazai.exe`.

### Option 2: Shareable build (no key included)

Safe to give to other people. Each user enters their own key once.

```bash
pip install requests customtkinter pyinstaller
pyinstaller --onefile --windowed --name "V-Scan by dazai" --collect-all customtkinter vscan.py
```

The result is `dist/V-Scan by dazai.exe`.

---

## 🧭 How to read the results

| Verdict | Meaning |
|---|---|
| 🟢 **Clean** | No engine flagged the item. |
| 🟡 **Suspicious** | One to four engines flagged it, or an engine marked it suspicious. This may be a false positive, so check the engine list and be careful. |
| 🔴 **Dangerous** | Five or more engines flagged it as malicious. Don't open it. |

> ⚠️ "Clean" means no engine flagged the item. It does **not** guarantee a file is safe, especially for brand-new malware.

---

## 🔒 Privacy and security

- **Hash lookups don't upload your file.** Only the SHA-256 hash is sent to VirusTotal.
- **Uploaded files become visible** to VirusTotal's security community. Never upload private or sensitive files.
- Your API key is stored locally in `~/.vscan.json` (or baked into your personal build) and is only ever sent to VirusTotal.
- **Never commit your API key or a personal-build exe to GitHub.** Anyone with the exe can extract the key inside it.

---

## 🧰 Tech stack

- [Python](https://www.python.org/)
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) for the interface
- [Requests](https://requests.readthedocs.io/) for the HTTP calls
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [PyInstaller](https://pyinstaller.org/) for packaging

---

## 📁 Project structure

```
V-Scan/
├── vscan.py        # the application
├── build.py        # builds a personal .exe with your API key baked in
├── assets/
│   └── screenshot.png
└── README.md
```

---

## 🗺️ Roadmap

- [ ] Scan history tab
- [ ] Drag-and-drop files
- [ ] Scan whole folders
- [ ] Right-click "Scan with V-Scan" in Windows Explorer
- [ ] Custom app icon

---

## ⚠️ Disclaimer

V-Scan is a front end for VirusTotal's public API and is not affiliated with or endorsed by VirusTotal or Google. Results come from third-party antivirus engines and can include false positives and false negatives. Use it as one tool among many, not a replacement for good security habits.

---

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">

Made with ☕ by **dazai**

If you find this useful, consider giving it a ⭐

</div>
