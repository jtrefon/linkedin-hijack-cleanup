<#
.SYNOPSIS
  Scan for malicious Chrome/Edge/Brave extensions & info-stealer droppers
  linked to the 2024–25 LinkedIn account-takeover campaigns.
.DESCRIPTION
  This script scans for and optionally cleans:
  1. Malicious browser extensions (Chrome, Edge, Brave)
  2. Info-stealer dropper files in temp directories
  3. LinkedIn cookies that attackers may have stolen
.PARAMETER Scan
  Run in scan-only mode (default)
.PARAMETER Clean
  Run in clean mode (will delete malicious content after confirmation)
.PARAMETER Verbose
  Display detailed progress information
.EXAMPLE
  .\clean_linkedin_attack.ps1 -Scan
.EXAMPLE
  .\clean_linkedin_attack.ps1 -Clean
.NOTES
  Author: Jacek Trefon
#>

[CmdletBinding()]
param(
    [switch]$Scan,
    [switch]$Clean,
    [switch]$VerboseOutput
)

# Set ErrorActionPreference to continue so the script doesn't stop on non-critical errors
$ErrorActionPreference = "Continue"

# ----------  CONFIG  ----------
$MalExt = @(
    # Original known malicious extensions
    "ndlbedplllcgconngcnfmkadhokfaaln", # GraphQL Network Inspector
    "ihcjicgdanjaechkgeegckofjjedodee", # Cyberhaven DLP
    "kjfmedjfbdalbgkmlfkgcnijgohlogoh", # VPNCity
    "jonbigdnokeokgnagfghjckepjplpaco", # Uvoice
    
    # Additional known malicious extensions
    "mdjgbmpkonefpnmglndfohjpicbmjlnb",
    "jnhgnonknehpejjnehehllkliplmbmhn",
    "inejjjikomlbaahobecdaoaillmllcgm",
    "cbclhpfgoncbpidmbpnfmiknmemhhhcd",
    "hloblpeplfiajnfdengendhdnpmdgvhc",
    "gcpkaokbjmnkdolkiaoklkbgiecflhpe"
)

$StealerNames = @(
    "Pictore.exe", "saved.exe", "random.exe", "smss.exe",
    "App_*.exe", "app-64.7z", "nsis7z.dll", "vpnpt.exe",
    "data.dat", "client.exe", "broker.exe", "svchost.dat",
    "update.exe", "chrome_update.exe", "update.bat"
)

$DaysBack = 30

# ----------  FUNCTIONS  ----------

function Write-VerboseLog {
    param([string]$Message)
    
    if ($VerboseOutput) {
        Write-Host "[INFO] $Message" -ForegroundColor Cyan
    }
}

function Get-BrowserProfiles {
    param(
        [string]$BrowserName,
        [string]$BasePath
    )
    
    $profiles = @()
    
    if (Test-Path -Path $BasePath) {
        # Get Default profile
        $defaultProfile = Join-Path -Path $BasePath -ChildPath "Default"
        if (Test-Path -Path $defaultProfile) {
            $profiles += @{
                "Path" = $defaultProfile
                "Name" = "Default"
            }
        }
        
        # Get additional profiles
        Get-ChildItem -Path $BasePath -Directory | Where-Object { $_.Name -like "Profile*" } | ForEach-Object {
            $profiles += @{
                "Path" = $_.FullName
                "Name" = $_.Name
            }
        }
    }
    
    return $profiles
}

function Get-ExtensionFolders {
    $extensionPaths = @()
    
    # Chrome
    $chromeBasePath = "$Env:LOCALAPPDATA\Google\Chrome\User Data"
    $chromeProfiles = Get-BrowserProfiles -BrowserName "Chrome" -BasePath $chromeBasePath
    
    # Edge
    $edgeBasePath = "$Env:LOCALAPPDATA\Microsoft\Edge\User Data"
    $edgeProfiles = Get-BrowserProfiles -BrowserName "Edge" -BasePath $edgeBasePath
    
    # Brave
    $braveBasePath = "$Env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    $braveProfiles = Get-BrowserProfiles -BrowserName "Brave" -BasePath $braveBasePath
    
    # Add extension folders for all profiles
    $allProfiles = $chromeProfiles + $edgeProfiles + $braveProfiles
    
    foreach ($profile in $allProfiles) {
        $extensionPath = Join-Path -Path $profile.Path -ChildPath "Extensions"
        if (Test-Path -Path $extensionPath) {
            $extensionPaths += $extensionPath
            Write-VerboseLog "Found extensions directory: $extensionPath"
        }
    }
    
    return $extensionPaths
}

function Find-MaliciousExtensions {
    $extHits = @()
    $count = 0
    
    Write-Host "Scanning for malicious browser extensions..." -ForegroundColor Blue
    
    # Get all extension folders
    $extensionPaths = Get-ExtensionFolders
    
    foreach ($path in $extensionPaths) {
        Write-VerboseLog "Checking extensions in: $path"
        
        try {
            # Get all extension directories
            $extensions = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue
            
            foreach ($ext in $extensions) {
                $count++
                
                # Check if extension ID is in our list of malicious extensions
                if ($MalExt -contains $ext.Name) {
                    $extHits += $ext
                    Write-VerboseLog "FOUND malicious extension: $($ext.FullName)"
                }
            }
        }
        catch {
            Write-VerboseLog "Error scanning $path`: $_"
        }
    }
    
    Write-VerboseLog "Scanned $count extension directories"
    
    return $extHits
}

function Get-TempDirectories {
    $tempDirs = @(
        "$Env:TEMP",
        "$Env:APPDATA",
        "$Env:LOCALAPPDATA\Temp",
        "$Env:USERPROFILE\Downloads",
        "$Env:PROGRAMDATA\Temp"
    )
    
    # Filter to only directories that exist
    $existingDirs = $tempDirs | Where-Object { Test-Path -Path $_ }
    
    foreach ($dir in $existingDirs) {
        Write-VerboseLog "Found temp directory: $dir"
    }
    
    return $existingDirs
}

function Find-StealerFiles {
    $fileHits = @()
    $count = 0
    
    Write-Host "Scanning for suspicious files..." -ForegroundColor Blue
    
    # Get temp directories to scan
    $tempDirs = Get-TempDirectories
    
    # Current date for comparison
    $now = Get-Date
    
    foreach ($dir in $tempDirs) {
        Write-VerboseLog "Scanning directory: $dir"
        
        try {
            # Get all files in the directory (recursively)
            Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $count++
                
                if ($count % 1000 -eq 0) {
                    Write-VerboseLog "Scanned $count files..."
                }
                
                # Check if file was modified within DaysBack
                if (($now - $_.LastWriteTime).Days -le $DaysBack) {
                    # Check if filename matches any suspicious patterns
                    foreach ($pattern in $StealerNames) {
                        if ($_.Name -like $pattern) {
                            $fileHits += $_
                            Write-VerboseLog "FOUND suspicious file: $($_.FullName)"
                            break
                        }
                    }
                }
            }
        }
        catch {
            Write-VerboseLog "Error scanning $dir`: $_"
        }
    }
    
    Write-VerboseLog "Scanned a total of $count files"
    
    return $fileHits
}

function Get-CookieDatabases {
    $cookieDbs = @()
    
    # Chrome
    $chromeBasePath = "$Env:LOCALAPPDATA\Google\Chrome\User Data"
    $chromeProfiles = Get-BrowserProfiles -BrowserName "Chrome" -BasePath $chromeBasePath
    
    # Edge
    $edgeBasePath = "$Env:LOCALAPPDATA\Microsoft\Edge\User Data"
    $edgeProfiles = Get-BrowserProfiles -BrowserName "Edge" -BasePath $edgeBasePath
    
    # Brave
    $braveBasePath = "$Env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    $braveProfiles = Get-BrowserProfiles -BrowserName "Brave" -BasePath $braveBasePath
    
    # Add cookie databases for all profiles
    $allProfiles = $chromeProfiles + $edgeProfiles + $braveProfiles
    
    foreach ($profile in $allProfiles) {
        $cookiePath = Join-Path -Path $profile.Path -ChildPath "Network\Cookies"
        if (Test-Path -Path $cookiePath) {
            $cookieDbs += @{
                "Path" = $cookiePath
                "Name" = "$($profile.Name) ($(Split-Path -Path (Split-Path -Path $profile.Path -Parent) -Leaf))"
            }
            Write-VerboseLog "Found cookie database: $cookiePath"
        }
    }
    
    return $cookieDbs
}

function Wipe-LinkedInCookies {
    $wiped = 0
    
    Write-Host "Checking for LinkedIn cookies..." -ForegroundColor Blue
    
    # Check if sqlite3 is available
    $sqlite3Path = Get-Command sqlite3 -ErrorAction SilentlyContinue
    if (-not $sqlite3Path) {
        Write-Host "Error: sqlite3 not found. Cannot clean cookies." -ForegroundColor Red
        Write-Host "Please install sqlite3 or add it to your PATH."
        return
    }
    
    # Get all cookie databases
    $cookieDbs = Get-CookieDatabases
    
    foreach ($db in $cookieDbs) {
        try {
            # Create backup first
            $backupPath = "$($db.Path).bak"
            Copy-Item -Path $db.Path -Destination $backupPath -Force
            Write-VerboseLog "Created backup: $backupPath"
            
            # Count LinkedIn cookies
            $countQuery = "SELECT COUNT(*) FROM cookies WHERE host_key LIKE '%linkedin.com';"
            $count = & sqlite3 $db.Path $countQuery
            
            if ($count -gt 0) {
                # Delete LinkedIn cookies
                $deleteQuery = "DELETE FROM cookies WHERE host_key LIKE '%linkedin.com';"
                & sqlite3 $db.Path $deleteQuery
                
                $wiped += $count
                Write-Host "Wiped $count LinkedIn cookies from $($db.Name) (backup: $backupPath)" -ForegroundColor Green
            }
            elseif ($VerboseOutput) {
                Write-Host "No LinkedIn cookies found in $($db.Name)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-VerboseLog "Error processing cookie database $($db.Path): $_"
        }
    }
    
    if ($wiped -eq 0) {
        Write-Host "No LinkedIn cookies found in any browser" -ForegroundColor Yellow
    }
    else {
        Write-Host "Total LinkedIn cookies wiped: $wiped" -ForegroundColor Green
    }
}

# ----------  MAIN  ----------

# If neither -Scan nor -Clean specified, default to Scan
if (-not $Scan -and -not $Clean) {
    $Scan = $true
}

if ($VerboseOutput) {
    Write-Host "[INFO] PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host "[INFO] Operating System: $([Environment]::OSVersion.VersionString)" -ForegroundColor Cyan
    Write-Host "[INFO] User Profile: $Env:USERPROFILE" -ForegroundColor Cyan
}

Write-Host "Starting LinkedIn-Hijack-Cleanup scan..." -ForegroundColor Blue
Write-Host "This might take a few minutes, please be patient." -ForegroundColor Yellow

# Measure execution time
$startTime = Get-Date

# Find malicious extensions and stealer files
$extHits = Find-MaliciousExtensions
$stealHits = Find-StealerFiles

# Calculate execution time
$duration = (Get-Date) - $startTime
$durationSeconds = [math]::Round($duration.TotalSeconds, 1)

# Display scan report
Write-Host "`n==== SCAN REPORT (completed in ${durationSeconds}s) ====" -ForegroundColor Green
Write-Host "Malicious extensions ($($extHits.Count)):" -ForegroundColor Blue
foreach ($ext in $extHits) {
    Write-Host "  $($ext.FullName)"
}

Write-Host "`nSuspicious files ($($stealHits.Count)):" -ForegroundColor Blue
foreach ($file in $stealHits) {
    Write-Host "  $($file.FullName)"
}

if ($extHits.Count -eq 0 -and $stealHits.Count -eq 0) {
    Write-Host "`nNo malicious content detected!" -ForegroundColor Green
}

# If not in clean mode, ask user if they want to clean
if (-not $Clean) {
    Write-Host "`nOptions:" -ForegroundColor Yellow
    $choice = Read-Host "[1]=Report only  [2]=Clean flagged items  [3]=Quit"
    if ($choice -eq "2") {
        $Clean = $true
    }
    elseif ($choice -eq "3") {
        exit
    }
}

# Clean if requested
if ($Clean) {
    if ($extHits.Count -gt 0 -or $stealHits.Count -gt 0) {
        Write-Host "`nCleaning flagged items..." -ForegroundColor Blue
        
        # Remove malicious extensions
        foreach ($ext in $extHits) {
            try {
                Remove-Item -Path $ext.FullName -Recurse -Force -ErrorAction Stop
                Write-Host "Removed extension: $($ext.FullName)" -ForegroundColor Green
            }
            catch {
                Write-Host "Error removing $($ext.FullName): $_" -ForegroundColor Red
            }
        }
        
        # Remove suspicious files
        foreach ($file in $stealHits) {
            try {
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                Write-Host "Removed file: $($file.FullName)" -ForegroundColor Green
            }
            catch {
                Write-Host "Error removing $($file.FullName): $_" -ForegroundColor Red
            }
        }
        
        # Wipe LinkedIn cookies
        Write-Host "`nWiping LinkedIn cookies..." -ForegroundColor Blue
        Wipe-LinkedInCookies
        
        Write-Host "`nCleanup complete. Backups kept alongside originals." -ForegroundColor Green
    }
    else {
        Write-Host "`nNo malicious content to clean, but wiping LinkedIn cookies as requested..." -ForegroundColor Yellow
        Wipe-LinkedInCookies
        Write-Host "`nCookie cleanup complete." -ForegroundColor Green
    }
}
