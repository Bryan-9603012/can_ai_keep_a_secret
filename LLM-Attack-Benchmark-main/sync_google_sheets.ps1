param(
  [string]$SpreadsheetId = "1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM",
  [string]$Credentials = "credentials/service-account.json",
  [string]$ReportDir = "",
  [switch]$NoRaw,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$PythonExe = "python"
if (Test-Path ".venv/Scripts/python.exe") {
  $PythonExe = ".venv/Scripts/python.exe"
}

if ([string]::IsNullOrWhiteSpace($SpreadsheetId) -and -not $DryRun) {
  $SpreadsheetId = Read-Host "Google Spreadsheet ID"
}
if ([string]::IsNullOrWhiteSpace($SpreadsheetId) -and $DryRun) {
  $SpreadsheetId = "1oSQ5SqSVDjNxam7SR7R2VHovcnIaQfsCQMZNsJeczXM"
}
if ([string]::IsNullOrWhiteSpace($Credentials)) {
  $Credentials = Read-Host "Service account JSON path"
}

$argsList = @("src/google_sheets_sync.py")
if (-not [string]::IsNullOrWhiteSpace($SpreadsheetId)) { $argsList += @("--spreadsheet-id", $SpreadsheetId) }
if (-not [string]::IsNullOrWhiteSpace($Credentials)) { $argsList += @("--credentials", $Credentials) }
if (-not [string]::IsNullOrWhiteSpace($ReportDir)) { $argsList += @("--report-dir", $ReportDir) }
if ($NoRaw) { $argsList += "--no-raw" }
if ($DryRun) { $argsList += "--dry-run" }

& $PythonExe @argsList
