#!/usr/bin/env python3
"""
Cross-platform scanner & optional cleaner for LinkedIn-hijack IoCs.
Run with:  python3 clean_linkedin_attack.py --scan  (or --clean)
"""
import argparse, pathlib, os, shutil, sqlite3, sys, time, logging, platform

# Extended list of malicious extensions
MAL_EXT = {
    "ndlbedplllcgconngcnfmkadhokfaaln", "ihcjicgdanjaechkgeegckofjjedodee",
    "kjfmedjfbdalbgkmlfkgcnijgohlogoh", "jonbigdnokeokgnagfghjckepjplpaco",
    # Additional known malicious extensions
    "mdjgbmpkonefpnmglndfohjpicbmjlnb", "jnhgnonknehpejjnehehllkliplmbmhn",
    "inejjjikomlbaahobecdaoaillmllcgm", "cbclhpfgoncbpidmbpnfmiknmemhhhcd",
    "hloblpeplfiajnfdengendhdnpmdgvhc", "gcpkaokbjmnkdolkiaoklkbgiecflhpe"
}
STEALER  = {"Pictore.exe", "saved.exe", "random.exe", "smss.exe",
            "App_", "app-64.7z", "nsis7z.dll", "vpnpt.exe", 
            "data.dat", "client.exe", "broker.exe", "svchost.dat",
            "update.exe", "chrome_update.exe", "update.bat"}  # prefix match for App_
DAYS = 30 * 24 * 3600

def find_browser_paths():
    """Find browser paths across various OS configurations"""
    paths = []
    home = pathlib.Path.home()
    
    # Windows paths
    if sys.platform.startswith("win"):
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            # Chrome paths (including user profiles)
            chrome_base = pathlib.Path(local_app_data) / "Google/Chrome/User Data"
            if chrome_base.exists():
                # Check for all profiles
                for profile in chrome_base.glob("*"):
                    if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                        paths.append(profile / "Extensions")
            
            # Edge paths (including user profiles)
            edge_base = pathlib.Path(local_app_data) / "Microsoft/Edge/User Data"
            if edge_base.exists():
                for profile in edge_base.glob("*"):
                    if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                        paths.append(profile / "Extensions")
                        
            # Brave paths
            brave_base = pathlib.Path(local_app_data) / "BraveSoftware/Brave-Browser/User Data"
            if brave_base.exists():
                for profile in brave_base.glob("*"):
                    if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                        paths.append(profile / "Extensions")
    
    # macOS paths
    elif sys.platform == "darwin":
        # Chrome (macOS)
        paths.append(home / "Library/Application Support/Google/Chrome/Default/Extensions")
        paths.append(home / "Library/Application Support/Google/Chrome/Profile 1/Extensions")
        
        # Check for additional Chrome profiles
        chrome_base = home / "Library/Application Support/Google/Chrome"
        if chrome_base.exists():
            for profile in chrome_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    paths.append(profile / "Extensions")
        
        # Edge (macOS)
        paths.append(home / "Library/Application Support/Microsoft Edge/Default/Extensions")
        
        # Brave (macOS)
        paths.append(home / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions")
    
    # Linux paths
    else:
        # Chrome (Linux)
        paths.append(home / ".config/google-chrome/Default/Extensions")
        chrome_base = home / ".config/google-chrome"
        if chrome_base.exists():
            for profile in chrome_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    paths.append(profile / "Extensions")
        
        # Edge (Linux)
        paths.append(home / ".config/microsoft-edge/Default/Extensions")
        
        # Brave (Linux)
        paths.append(home / ".config/BraveSoftware/Brave-Browser/Default/Extensions")
    
    return paths

def temp_dirs():
    """Find temp directories where malware often drops files"""
    dirs = []
    home = pathlib.Path.home()
    
    # Cross-platform temp dirs
    if "TEMP" in os.environ:
        dirs.append(pathlib.Path(os.environ["TEMP"]))
    
    # Windows temp dirs
    if sys.platform.startswith("win"):
        if "LOCALAPPDATA" in os.environ:
            dirs.append(pathlib.Path(os.environ["LOCALAPPDATA"]) / "Temp")
        if "APPDATA" in os.environ:
            dirs.append(pathlib.Path(os.environ["APPDATA"]))
        if "PROGRAMDATA" in os.environ:
            dirs.append(pathlib.Path(os.environ["PROGRAMDATA"]))
        dirs.append(pathlib.Path("C:/Windows/Temp"))
    
    # macOS temp dirs
    elif sys.platform == "darwin":
        dirs.append(pathlib.Path("/tmp"))
        dirs.append(home / "Library/Caches")
        dirs.append(home / "Library/Application Support")
        dirs.append(home / "Downloads")
    
    # Linux temp dirs
    else:
        dirs.append(pathlib.Path("/tmp"))
        dirs.append(home / ".cache")
        dirs.append(home / "Downloads")
        dirs.append(home / ".local/share")
    
    return dirs

def scan(verbose=False):
    """Scan for malicious extensions and stealer files"""
    now = time.time()
    ext_hits, file_hits = [], []
    scan_count = 0
    
    # Scan browser extension directories
    if verbose:
        print("Scanning browser extensions...")
        
    for ext_path in find_browser_paths():
        if not ext_path.exists():
            continue
            
        if verbose:
            print(f"Checking {ext_path}")
            
        try:
            for d in ext_path.iterdir():
                scan_count += 1
                if d.name in MAL_EXT:
                    ext_hits.append(d)
        except (PermissionError, OSError) as e:
            if verbose:
                print(f"Error scanning {ext_path}: {e}")
    
    # Scan temp directories
    if verbose:
        print("\nScanning temp directories for stealer files...")
        
    for temp_dir in temp_dirs():
        if not temp_dir.exists():
            continue
            
        if verbose:
            print(f"Checking {temp_dir}")
            
        try:
            for f in temp_dir.rglob("*"):
                scan_count += 1
                if scan_count % 10000 == 0 and verbose:
                    print(f"Scanned {scan_count} items...")
                    
                if f.is_file():
                    try:
                        # Only check recently modified files
                        if now - f.stat().st_mtime <= DAYS:
                            base = f.name
                            if base in STEALER or any(base.startswith(x) for x in ("App_",)):
                                file_hits.append(f)
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError) as e:
            if verbose:
                print(f"Error scanning {temp_dir}: {e}")
    
    # Additionally, scan Downloads folder for recently modified suspicious files
    home = pathlib.Path.home()
    downloads = home / "Downloads"
    if downloads.exists():
        if verbose:
            print(f"Scanning Downloads folder: {downloads}")
        try:
            for f in downloads.glob("*"):
                if f.is_file():
                    try:
                        if now - f.stat().st_mtime <= DAYS:
                            base = f.name
                            if base in STEALER or any(base.startswith(x) for x in ("App_",)):
                                file_hits.append(f)
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError) as e:
            if verbose:
                print(f"Error scanning Downloads: {e}")
    
    if verbose:
        print(f"Scan complete. Checked {scan_count} items.")
        
    return ext_hits, file_hits

def find_cookie_databases():
    """Find cookie databases across different browsers and OS configurations"""
    cookie_dbs = []
    home = pathlib.Path.home()
    
    # Windows paths
    if sys.platform.startswith("win"):
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            chrome_base = pathlib.Path(local_app_data) / "Google/Chrome/User Data"
            if chrome_base.exists():
                for profile in chrome_base.glob("*"):
                    if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                        cookie_dbs.append((profile / "Network/Cookies", "Chrome " + profile.name))
            
            edge_base = pathlib.Path(local_app_data) / "Microsoft/Edge/User Data"
            if edge_base.exists():
                for profile in edge_base.glob("*"):
                    if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                        cookie_dbs.append((profile / "Network/Cookies", "Edge " + profile.name))
                        
            brave_base = pathlib.Path(local_app_data) / "BraveSoftware/Brave-Browser/User Data"
            if brave_base.exists():
                for profile in brave_base.glob("*"):
                    if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                        cookie_dbs.append((profile / "Network/Cookies", "Brave " + profile.name))
    
    # macOS paths
    elif sys.platform == "darwin":
        chrome_base = home / "Library/Application Support/Google/Chrome"
        if chrome_base.exists():
            for profile in chrome_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    cookie_dbs.append((profile / "Cookies", "Chrome " + profile.name))
        
        edge_base = home / "Library/Application Support/Microsoft Edge"
        if edge_base.exists():
            for profile in edge_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    cookie_dbs.append((profile / "Cookies", "Edge " + profile.name))
        
        brave_base = home / "Library/Application Support/BraveSoftware/Brave-Browser"
        if brave_base.exists():
            for profile in brave_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    cookie_dbs.append((profile / "Cookies", "Brave " + profile.name))
    
    # Linux paths
    else:
        chrome_base = home / ".config/google-chrome"
        if chrome_base.exists():
            for profile in chrome_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    cookie_dbs.append((profile / "Cookies", "Chrome " + profile.name))
        
        edge_base = home / ".config/microsoft-edge"
        if edge_base.exists():
            for profile in edge_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    cookie_dbs.append((profile / "Cookies", "Edge " + profile.name))
        
        brave_base = home / ".config/BraveSoftware/Brave-Browser"
        if brave_base.exists():
            for profile in brave_base.glob("*"):
                if profile.is_dir() and (profile.name == "Default" or profile.name.startswith("Profile")):
                    cookie_dbs.append((profile / "Cookies", "Brave " + profile.name))
    
    return cookie_dbs

def wipe_cookies(verbose=False):
    """Wipe LinkedIn cookies from all browser profiles"""
    cookie_databases = find_cookie_databases()
    wiped = 0
    
    for cookie_db, browser_name in cookie_databases:
        if not cookie_db.exists():
            continue
            
        try:
            # Create backup first
            backup_path = cookie_db.with_suffix(".bak")
            shutil.copy2(cookie_db, backup_path)
            
            try:
                # Connect to the cookie database and delete LinkedIn cookies
                with sqlite3.connect(cookie_db) as db:
                    cursor = db.cursor()
                    cursor.execute("SELECT COUNT(*) FROM cookies WHERE host_key LIKE '%linkedin.com'")
                    count = cursor.fetchone()[0]
                    
                    if count > 0:
                        cursor.execute("DELETE FROM cookies WHERE host_key LIKE '%linkedin.com'")
                        db.commit()
                        wiped += count
                        print(f"Wiped {count} LinkedIn cookies from {browser_name} (backup: {backup_path})")
                    elif verbose:
                        print(f"No LinkedIn cookies found in {browser_name}")
            except sqlite3.Error as e:
                if verbose:
                    print(f"SQLite error with {cookie_db}: {e}")
        except (PermissionError, OSError) as e:
            if verbose:
                print(f"Error backing up {cookie_db}: {e}")
    
    if wiped == 0 and verbose:
        print("No LinkedIn cookies found in any browser")
    elif wiped > 0:
        print(f"Total LinkedIn cookies wiped: {wiped}")

def main():
    ap = argparse.ArgumentParser(description="LinkedIn Hijack Scanner & Cleaner")
    ap.add_argument("--clean", action="store_true", help="delete flagged items & wipe LinkedIn cookies")
    ap.add_argument("--scan", action="store_true", help="scan only (default)")
    ap.add_argument("--verbose", "-v", action="store_true", help="display detailed progress information")
    args = ap.parse_args()
    
    if args.verbose:
        print(f"Starting scan on {platform.system()} {platform.release()}")
        print(f"Python {sys.version} at {sys.executable}")
        print(f"Home directory: {pathlib.Path.home()}")
    
    print("Scanning system for malicious content, please wait...")
    start_time = time.time()
    
    ext, files = scan(args.verbose)
    
    scan_time = time.time() - start_time
    
    print(f"\n==== SCAN REPORT ({scan_time:.1f} seconds) ====")
    print(f"Malicious extensions ({len(ext)}):")
    for e in ext:
        print(f"  {e}")
    
    print(f"\nSuspicious files ({len(files)}):")
    for f in files:
        print(f"  {f}")
    
    if len(ext) == 0 and len(files) == 0:
        print("\nNo malicious content detected!")
    
    if args.clean and (len(ext) > 0 or len(files) > 0):
        print("\nCleaning flagged items...")
        for e in ext:
            try:
                shutil.rmtree(e, ignore_errors=True)
                print(f"Removed extension: {e}")
            except Exception as err:
                print(f"Error removing {e}: {err}")
                
        for f in files:
            try:
                f.unlink(missing_ok=True)
                print(f"Removed file: {f}")
            except Exception as err:
                print(f"Error removing {f}: {err}")
        
        print("\nWiping LinkedIn cookies...")
        wipe_cookies(args.verbose)
        print("\nCleanup complete. Backups kept alongside originals.")
    elif args.clean:
        print("\nNo malicious content to clean, but wiping LinkedIn cookies as requested...")
        wipe_cookies(args.verbose)
        print("\nCookie cleanup complete.")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("--scan")
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nError: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            traceback.print_exc()
