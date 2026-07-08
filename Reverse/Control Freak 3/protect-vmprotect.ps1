param(
    [string]$VmProtectCon = "VMProtect_Con.exe",
    [string]$LinuxProject = "vmprotect\chall-4-linux.vmp",
    [string]$WindowsProject = "vmprotect\chall-4-windows.vmp",
    [switch]$InPlace
)

$ErrorActionPreference = "Stop"

# Optional legacy experiment only. The intended chall-4 release path is the
# custom VM binary from gen.cpp, without VMProtect as a required dependency.

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$tool = Get-Command $VmProtectCon -ErrorAction SilentlyContinue
if (-not $tool) {
    throw "VMProtect console tool not found: $VmProtectCon"
}

$targets = @(
    @{
        Input = Join-Path $root "dist\chall-4"
        Output = Join-Path $root "dist\chall-4.vmp"
        Project = Join-Path $root $LinuxProject
    },
    @{
        Input = Join-Path $root "dist\chall-4.exe"
        Output = Join-Path $root "dist\chall-4.exe.vmp"
        Project = Join-Path $root $WindowsProject
    }
)

foreach ($target in $targets) {
    if (-not (Test-Path -LiteralPath $target.Input)) {
        throw "Missing input binary: $($target.Input)"
    }
    if (-not (Test-Path -LiteralPath $target.Project)) {
        throw "Missing VMProtect project file: $($target.Project)"
    }

    & $tool.Source $target.Input $target.Output "-pf" $target.Project
    if ($LASTEXITCODE -ne 0) {
        throw "VMProtect failed for $($target.Input)"
    }

    if ($InPlace) {
        Move-Item -LiteralPath $target.Output -Destination $target.Input -Force
    }
}
