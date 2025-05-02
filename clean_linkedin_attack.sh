#!/usr/bin/env bash
# LinkedIn Hijack Scanner & Cleaner
# Cross-platform scanner for LinkedIn account-takeover attacks
# Author: Jacek Trefon
# Updated: Fixed macOS compatibility issues

# Avoid using set -o nounset with arrays in older bash versions
set -o pipefail  # Return status of the last command in a pipeline that failed

# Detect OS
OS="$(uname -s)"
case "${OS}" in
  Linux*)     OS_TYPE=linux;;
  Darwin*)    OS_TYPE=macos;;
  MINGW*|CYGWIN*|MSYS*) OS_TYPE=windows;;
  *)          OS_TYPE=unknown;;
esac

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m' 
NC='\033[0m' # No Color

# Verbose mode flag
VERBOSE=0

# List of malicious extension IDs
MAL_EXT=(
  ndlbedplllcgconngcnfmkadhokfaaln ihcjicgdanjaechkgeegckofjjedodee 
  kjfmedjfbdalbgkmlfkgcnijgohlogoh jonbigdnokeokgnagfghjckepjplpaco
  # Additional known malicious extensions
  mdjgbmpkonefpnmglndfohjpicbmjlnb jnhgnonknehpejjnehehllkliplmbmhn
  inejjjikomlbaahobecdaoaillmllcgm cbclhpfgoncbpidmbpnfmiknmemhhhcd  
  hloblpeplfiajnfdengendhdnpmdgvhc gcpkaokbjmnkdolkiaoklkbgiecflhpe
)

# List of suspicious file patterns
STEALER=(
  Pictore.exe saved.exe random.exe smss.exe App_*.exe app-64.7z 
  nsis7z.dll vpnpt.exe data.dat client.exe broker.exe 
  svchost.dat update.exe chrome_update.exe update.bat
)

# Timeframe to check (in days)
DAYS=90

# -------------------------------
# Function definitions
# -------------------------------

# Print usage information
usage() {
  echo "Usage: $0 [OPTIONS]"
  echo "  --scan      Scan only (default)"
  echo "  --clean     Delete flagged items and wipe LinkedIn cookies"
  echo "  --verbose   Show detailed progress information"
  echo "  --help      Show this help message"
}

# Print a message if verbose mode is enabled
log_verbose() {
  if [ "$VERBOSE" -eq 1 ]; then
    echo -e "${BLUE}[INFO]${NC} $1" >&2
  fi
}

# Find browser extension directories
find_extension_dirs() {
  # Common Chrome/Edge/Brave locations across platforms
  if [ "$OS_TYPE" = "macos" ]; then
    # macOS browser locations
    for browser in "Google/Chrome" "Microsoft Edge" "BraveSoftware/Brave-Browser"; do
      local base_dir="$HOME/Library/Application Support/$browser"
      if [ -d "$base_dir" ]; then
        # Check for Default and Profile directories
        for profile in "$base_dir"/*; do
          if [ -d "$profile" ] && { [ "$(basename "$profile")" = "Default" ] || [[ "$(basename "$profile")" == Profile* ]]; }; then
            local ext_dir="$profile/Extensions"
            if [ -d "$ext_dir" ]; then
              echo "$ext_dir"
              log_verbose "Found extension directory: $ext_dir"
            fi
          fi
        done
      fi
    done
  elif [ "$OS_TYPE" = "linux" ]; then
    # Linux browser locations
    for browser in ".config/google-chrome" ".config/microsoft-edge" ".config/BraveSoftware/Brave-Browser"; do
      local base_dir="$HOME/$browser"
      if [ -d "$base_dir" ]; then
        # Check for Default and Profile directories
        for profile in "$base_dir"/*; do
          if [ -d "$profile" ] && { [ "$(basename "$profile")" = "Default" ] || [[ "$(basename "$profile")" == Profile* ]]; }; then
            local ext_dir="$profile/Extensions"
            if [ -d "$ext_dir" ]; then
              echo "$ext_dir"
              log_verbose "Found extension directory: $ext_dir"
            fi
          fi
        done
      fi
    done
  fi
}

# Find temporary directories to scan
find_temp_dirs() {
  # Common temp directories
  if [ "$OS_TYPE" = "macos" ]; then
    if [ -d "/tmp" ]; then
      echo "/tmp"
      log_verbose "Found temp directory: /tmp"
    fi
    if [ -d "$HOME/Library/Caches" ]; then
      echo "$HOME/Library/Caches"
      log_verbose "Found temp directory: $HOME/Library/Caches"
    fi
    if [ -d "$HOME/Library/Application Support" ]; then
      echo "$HOME/Library/Application Support"
      log_verbose "Found temp directory: $HOME/Library/Application Support"
    fi
    if [ -d "$HOME/Downloads" ]; then
      echo "$HOME/Downloads"
      log_verbose "Found temp directory: $HOME/Downloads"
    fi
  elif [ "$OS_TYPE" = "linux" ]; then
    if [ -d "/tmp" ]; then
      echo "/tmp"
      log_verbose "Found temp directory: /tmp"
    fi
    if [ -d "$HOME/.cache" ]; then
      echo "$HOME/.cache"
      log_verbose "Found temp directory: $HOME/.cache"
    fi
    if [ -d "$HOME/Downloads" ]; then
      echo "$HOME/Downloads"
      log_verbose "Found temp directory: $HOME/Downloads"
    fi
    if [ -d "$HOME/.local/share" ]; then
      echo "$HOME/.local/share"
      log_verbose "Found temp directory: $HOME/.local/share"
    fi
  fi
}

# Find cookie databases
find_cookie_dbs() {
  if [ "$OS_TYPE" = "macos" ]; then
    # macOS browser locations
    for browser in "Google/Chrome" "Microsoft Edge" "BraveSoftware/Brave-Browser"; do
      local base_dir="$HOME/Library/Application Support/$browser"
      if [ -d "$base_dir" ]; then
        # Check for Default and Profile directories
        for profile in "$base_dir"/*; do
          if [ -d "$profile" ] && { [ "$(basename "$profile")" = "Default" ] || [[ "$(basename "$profile")" == Profile* ]]; }; then
            local cookie_db="$profile/Cookies"
            if [ -f "$cookie_db" ]; then
              echo "$cookie_db"
              log_verbose "Found cookie database: $cookie_db"
            fi
          fi
        done
      fi
    done
  elif [ "$OS_TYPE" = "linux" ]; then
    # Linux browser locations
    for browser in ".config/google-chrome" ".config/microsoft-edge" ".config/BraveSoftware/Brave-Browser"; do
      local base_dir="$HOME/$browser"
      if [ -d "$base_dir" ]; then
        # Check for Default and Profile directories
        for profile in "$base_dir"/*; do
          if [ -d "$profile" ] && { [ "$(basename "$profile")" = "Default" ] || [[ "$(basename "$profile")" == Profile* ]]; }; then
            local cookie_db="$profile/Cookies"
            if [ -f "$cookie_db" ]; then
              echo "$cookie_db"
              log_verbose "Found cookie database: $cookie_db"
            fi
          fi
        done
      fi
    done
  fi
}

# Scan for malicious extensions
scan_extensions() {
  local scan_count=0
  
  # Get extension directories
  for dir in $(find_extension_dirs); do
    [ -d "$dir" ] || continue
    log_verbose "Checking extensions in: $dir"
    
    for ext in "$dir"/*; do
      [ -d "$ext" ] || continue
      scan_count=$((scan_count + 1))
      
      local ext_id=$(basename "$ext")
      for bad in "${MAL_EXT[@]}"; do
        if [ "$ext_id" = "$bad" ]; then
          echo "$ext"
          log_verbose "FOUND malicious extension: $ext"
          break
        fi
      done
    done
  done
  
  log_verbose "Scanned $scan_count extension directories"
}

# Scan for suspicious files
scan_files() {
  local scan_count=0
  
  # Get temp directories to scan
  for dir in $(find_temp_dirs) "$HOME/Downloads"; do
    [ -d "$dir" ] || continue
    log_verbose "Scanning directory: $dir"
    
    # Use find to locate recently modified files
    if [ "$OS_TYPE" = "macos" ]; then
      # macOS uses -mtime +/-n for days
      find_cmd="find \"$dir\" -type f -mtime -${DAYS} 2>/dev/null"
    else
      # Linux uses -mtime +/-n for days
      find_cmd="find \"$dir\" -type f -mtime -${DAYS} 2>/dev/null"
    fi
    
    # Execute find command and loop through results
    while IFS= read -r file; do
      [ -z "$file" ] && continue
      scan_count=$((scan_count + 1))
      
      if [ $((scan_count % 1000)) -eq 0 ]; then
        log_verbose "Scanned $scan_count files..."
      fi
      
      base_name=$(basename "$file")
      for pattern in "${STEALER[@]}"; do
        if [[ "$base_name" == $pattern ]]; then
          echo "$file"
          log_verbose "FOUND suspicious file: $file"
          break
        fi
      done
    done < <(eval "$find_cmd" || echo "")
  done
  
  log_verbose "Scanned a total of $scan_count files"
}

# Wipe LinkedIn cookies
wipe_cookies() {
  local wiped=0
  
  echo -e "${BLUE}Checking for LinkedIn cookies...${NC}"
  
  # Check if sqlite3 is available
  if ! command -v sqlite3 >/dev/null 2>&1; then
    echo -e "${RED}Error: sqlite3 not found. Cannot clean cookies.${NC}"
    echo "Please install sqlite3 with your package manager:"
    echo "  - Debian/Ubuntu: sudo apt install sqlite3"
    echo "  - Fedora: sudo dnf install sqlite"
    echo "  - macOS: brew install sqlite"
    return 1
  fi
  
  # Get cookie databases
  for db in $(find_cookie_dbs); do
    [ -f "$db" ] || continue
    
    # Create backup
    cp "$db" "${db}.bak"
    log_verbose "Created backup: ${db}.bak"
    
    # Count LinkedIn cookies
    count=$(sqlite3 "$db" "SELECT COUNT(*) FROM cookies WHERE host_key LIKE '%linkedin.com';" 2>/dev/null)
    
    if [ "$count" -gt 0 ]; then
      # Delete LinkedIn cookies
      sqlite3 "$db" "DELETE FROM cookies WHERE host_key LIKE '%linkedin.com';" 2>/dev/null
      wiped=$((wiped + count))
      echo -e "${GREEN}Wiped $count LinkedIn cookies from $(basename "$(dirname "$db")") (backup: ${db}.bak)${NC}"
    elif [ "$VERBOSE" -eq 1 ]; then
      echo -e "${YELLOW}No LinkedIn cookies found in $(basename "$(dirname "$db")")${NC}"
    fi
  done
  
  if [ "$wiped" -eq 0 ]; then
    echo -e "${YELLOW}No LinkedIn cookies found in any browser${NC}"
  else
    echo -e "${GREEN}Total LinkedIn cookies wiped: $wiped${NC}"
  fi
}

# -------------------------------
# Main script
# -------------------------------

# Process command line arguments
CLEAN=0
SCAN=1

while [ $# -gt 0 ]; do
  case "$1" in
    --clean)
      CLEAN=1
      ;;
    --scan)
      SCAN=1
      ;;
    --verbose)
      VERBOSE=1
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

# Print system information in verbose mode
if [ "$VERBOSE" -eq 1 ]; then
  echo -e "${BLUE}[INFO]${NC} Running on: $OS_TYPE ($(uname -a))"
  echo -e "${BLUE}[INFO]${NC} Home directory: $HOME"
fi

echo -e "${BLUE}Starting LinkedIn-Hijack-Cleanup scan...${NC}"
echo -e "${YELLOW}This might take a few minutes, please be patient.${NC}"

# Start time
start_time=$(date +%s)

# Scan for malicious extensions and collect results
echo -e "${BLUE}Scanning for malicious browser extensions...${NC}"
malicious_exts=()
while IFS= read -r ext; do
  [ -z "$ext" ] && continue
  malicious_exts+=("$ext")
done < <(scan_extensions)

# Scan for suspicious files and collect results
echo -e "${BLUE}Scanning for suspicious files...${NC}"
suspicious_files=()
while IFS= read -r file; do
  [ -z "$file" ] && continue
  suspicious_files+=("$file")
done < <(scan_files)

# End time
end_time=$(date +%s)
duration=$((end_time - start_time))

# Display report
echo -e "\n${GREEN}==== SCAN REPORT (completed in ${duration}s) ====${NC}"
echo -e "${BLUE}Malicious extensions (${#malicious_exts[@]}):${NC}"
for ext in "${malicious_exts[@]}"; do
  echo "  $ext"
done

echo -e "\n${BLUE}Suspicious files (${#suspicious_files[@]}):${NC}"
for file in "${suspicious_files[@]}"; do
  echo "  $file"
done

if [ ${#malicious_exts[@]} -eq 0 ] && [ ${#suspicious_files[@]} -eq 0 ]; then
  echo -e "\n${GREEN}No malicious content detected!${NC}"
fi

# Prompt for cleaning
if [ "$CLEAN" -eq 0 ]; then
  echo -e "\n${YELLOW}Options:${NC}"
  read -rp $'[1]=Report only  [2]=Clean flagged items  [3]=Quit : ' choice
  if [ "$choice" = "2" ]; then
    CLEAN=1
  elif [ "$choice" = "3" ]; then
    exit 0
  fi
fi

# Clean if requested
if [ "$CLEAN" -eq 1 ]; then
  if [ ${#malicious_exts[@]} -gt 0 ] || [ ${#suspicious_files[@]} -gt 0 ]; then
    echo -e "\n${BLUE}Cleaning flagged items...${NC}"
    
    # Remove malicious extensions
    for ext in "${malicious_exts[@]}"; do
      rm -rf "$ext"
      echo -e "${GREEN}Removed extension: $ext${NC}"
    done
    
    # Remove suspicious files
    for file in "${suspicious_files[@]}"; do
      rm -f "$file"
      echo -e "${GREEN}Removed file: $file${NC}"
    done
    
    # Wipe LinkedIn cookies
    echo -e "\n${BLUE}Wiping LinkedIn cookies...${NC}"
    wipe_cookies
    
    echo -e "\n${GREEN}Cleanup complete. Backups kept alongside originals.${NC}"
  else
    echo -e "\n${YELLOW}No malicious content to clean, but wiping LinkedIn cookies as requested...${NC}"
    wipe_cookies
    echo -e "\n${GREEN}Cookie cleanup complete.${NC}"
  fi
fi
