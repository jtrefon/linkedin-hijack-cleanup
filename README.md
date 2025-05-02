# LinkedIn-Hijack-Cleanup Kit

A **cross-platform "one-click" scanner and optional cleaner** that targets the *current wave* of LinkedIn account-takeover attacks (December 2024 → present).  
It hunts for:

* Hijacked Chrome / Edge / Brave extensions (35+ known IDs from the December-2024 supply-chain breach)  
* Lumma, RedLine and similar information-stealer droppers in your temp / cache folders  
* Live LinkedIn cookies that attackers replay to skip SMS-2FA

The kit ships as **three stand-alone scripts**—one each for *Windows (PowerShell)*, *macOS & Linux (bash)*, and *any OS (pure Python 3)*.  
Each script **only touches files in your user account**, offers a **"report-only" mode first**, and backs up LinkedIn cookies before it deletes anything.

---

## ⚠️ Legal Notice & Disclaimer ⚠️
> I, the author, am **NOT responsible** for any direct, indirect, incidental or consequential damage arising from the use or misuse of these scripts.  
> They are provided **"AS IS", in good faith**, for the sole purpose of helping fellow victims recover from this specific attack campaign.  
> **USE AT YOUR OWN RISK.**  
> Always keep current system backups and review the code before you run it.

---

## 1.  Quick Start for Non-Technical Users

| Your computer | Quick command (copy / paste) | What you'll see first |
|---------------|-----------------------------|-----------------------|
| **Windows 10 / 11** | 1. Download `clean_linkedin_attack.ps1` to **Downloads**  
2. Right-click **Start** → *Windows Terminal (Admin)*  
3. Run:<br/>```powershell -ExecutionPolicy Bypass -File "$HOME\Downloads\clean_linkedin_attack.ps1"``` | A blue PowerShell window with:  
`[1] Generate report only  [2] Clean flagged items  [3] Quit` |
| **macOS (Ventura / Sonoma)** | 1. Download `clean_linkedin_attack.sh` to **Downloads**  
2. Open *Terminal* (⌘ Space → "Terminal")  
3. Run:<br/>```bash chmod +x ~/Downloads/clean_linkedin_attack.sh && ~/Downloads/clean_linkedin_attack.sh``` | A scan report followed by the same menu |
| **Ubuntu / Debian / Fedora** | Same as macOS (replace `~/Downloads` with your path). Requires `sqlite3` (pre-installed on most distros). | |
| **Any OS with Python 3.8+** | 1. Download `clean_linkedin_attack.py`  
2. In a terminal:  
```bash python3 clean_linkedin_attack.py --scan```  
3. To clean:  
```bash python3 clean_linkedin_attack.py --clean``` | Text report → confirmation messages |

**Nothing is deleted automatically**. Choose option 2 (`Clean flagged items`) only after you review the report and you're comfortable.

All scripts support additional parameters like `--verbose` for detailed progress information.

---

## 2.  What the Scripts Do—Step by Step

1. **Scan browser extension folders** (`Extensions/` under Chrome, Edge & Brave)  
   *Compares every folder ID to the public list of 35+ compromised IDs across all browser profiles.*  
2. **Scan temp / cache directories** (`%TEMP%`, `%APPDATA%`, `/tmp`, `~/.cache`, Downloads folder)  
   *Looks for common Lumma / RedLine dropper filenames changed in the last 30 days.*  
3. **(Optional) Clear LinkedIn cookies only**  
   *Backs up your `Cookies` database, then removes rows where `host_key` contains `linkedin.com`—log-outs attackers.*  
4. **Create local backups** of anything it modifies (cookies → `Cookies.bak`).  
5. **Print a success summary**.

No registry edits, no system files, no elevation required (except PowerShell must run "as Admin" so it can remove files dropped in `%ProgramData%`).

---

## 3.  Troubleshooting & FAQs

| Problem | Fix |
|---------|-----|
| *PowerShell says "running scripts is disabled"* | Copy the exact command above; `-ExecutionPolicy Bypass` is temporary and applies only to this run. |
| *macOS says "cannot be opened because the developer cannot be verified"* | In Finder → Right-click the `.sh` file → **Open** → *Open*. Or run via Terminal (bypasses Gatekeeper for user scripts). |
| *`sqlite3` not found on Linux* | `sudo apt install sqlite3` (Debian/Ubuntu) or `sudo dnf install sqlite` (Fedora). |
| *Nothing is detected but my LinkedIn was hacked* | The attack vector may be a SIM-swap or a new extension ID. Update the scripts' IoC lists (see below) and rescan. |
| *Want to see detailed progress* | Add `--verbose` flag to any script when running, e.g., `./clean_linkedin_attack.sh --verbose` |

---

## 4.  Updating the IoC Lists

The arrays at the top of each script `MAL_EXT` and `STEALER` are plain text.  
If new malicious extension IDs or file names surface:

1. Open the script in any text editor.  
2. Add the new ID or filename as a quoted string in the corresponding array.  
3. Save and re-run the scan.

---

## 5.  License

Distributed under the **MIT License** – see [`LICENSE`](LICENSE) for details.  
In short: you can copy, modify, distribute, and use the code for any purpose, but **please keep the original copyright notice and disclaimer**.

---

## 6.  Improvements & Features

The latest version includes these enhancements:

* Support for Brave browser in addition to Chrome and Edge
* Scanning of all browser profiles, not just the default one
* Robust error handling for better cross-platform compatibility
* Expanded scanning of common malware locations including the Downloads folder
* Improved detection of file patterns with more IoCs
* Verbose logging option for troubleshooting (add `--verbose` to any script)
* Better cookie handling across all browser profiles

---

## 7.  Kudos & Contact

* IoC sources: Microsoft MSTIC, Proofpoint, The Hacker News, Talos  
* Author: *Jacek Trefon* – feel free to open an **Issue** or **Pull Request** if you spot new indicators or bugs.  
* Spread the word: share this repo with anyone seeing strange LinkedIn logins from Texas (or anywhere else).

Stay safe & keep your 2FA app-based! 🤖
