<#
.SYNOPSIS
    Configures IIS HTTP bindings from domains file

.PARAMETER DomainsFile
    Path to domains list file

.PARAMETER SiteName
    IIS site name (default: prod-pronet)

.PARAMETER AppPoolName
    App pool name (default: prod-pronet)
#>

param(
    [Parameter(Mandatory)]
    [string]$DomainsFile,
    
    [string]$SiteName = "prod-pronet",
    [string]$AppPoolName = "prod-pronet",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Import-Module WebAdministration

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" }
function LogSuccess($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Green }
function LogError($msg) { Write-Host "[ERROR] $msg" -ForegroundColor Red }

Log "=== IIS HTTP Bindings ==="

# Read domains
if (-not (Test-Path $DomainsFile)) {
    LogError "Domains file not found: $DomainsFile"
    exit 1
}

$domains = Get-Content $DomainsFile | 
    Where-Object { $_ -and $_ -notmatch '^\s*#' } | 
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ }

if ($domains.Count -eq 0) {
    LogError "No domains found"
    exit 1
}

Log "Domains: $($domains.Count)"
$domains | ForEach-Object { Log "  - $_" }

if ($DryRun) {
    Log "=== DRY RUN ==="
    exit 0
}

# Check site
if (-not (Test-Path "IIS:\Sites\$SiteName")) {
    LogError "Site not found: $SiteName"
    exit 1
}

# Stop app pool
$pool = Get-Item "IIS:\AppPools\$AppPoolName" -ErrorAction SilentlyContinue
if ($pool -and $pool.State -eq "Started") {
    Log "Stopping app pool..."
    Stop-WebAppPool $AppPoolName
    Start-Sleep 3
}

# Create bindings
$created = 0
$skipped = 0

foreach ($domain in $domains) {
    $existing = Get-WebBinding -Name $SiteName -Protocol "http" | 
        Where-Object { $_.bindingInformation -eq "*:80:$domain" }
    
    if ($existing) {
        Log "  $domain - exists"
        $skipped++
    } else {
        New-WebBinding -Name $SiteName -IPAddress "*" -Port 80 -HostHeader $domain
        Log "  $domain - created"
        $created++
    }
}

# Start app pool
if ($pool) {
    Log "Starting app pool..."
    Start-WebAppPool $AppPoolName
    Start-Sleep 2
    Log "App pool: $((Get-Item "IIS:\AppPools\$AppPoolName").State)"
}

LogSuccess "=== Done: $created created, $skipped skipped ==="
