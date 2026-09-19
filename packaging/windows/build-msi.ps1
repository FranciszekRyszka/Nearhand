# Build the agent's MSI: target\release\nearhand-agent-<version>-x64.msi.
#
# Needs WiX 5 and its Util extension:
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add -g WixToolset.Util.wixext/5.0.2
# (-Wix points at wix.exe when it is not on the PATH.)
param(
    [string]$Wix = 'wix',
    [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."

if (-not $NoBuild) {
    cargo build --release -p nearhand-agent --manifest-path "$root\Cargo.toml"
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

# MSI versions are three numbers; the crate's version is.
$version = (Select-String -Path "$root\crates\agent\Cargo.toml" -Pattern '^version = "([^"]+)"').Matches[0].Groups[1].Value
$exe = "$root\target\release\nearhand-agent.exe"
$out = "$root\target\release\nearhand-agent-$version-x64.msi"

& $Wix build "$PSScriptRoot\agent.wxs" `
    -arch x64 `
    -ext WixToolset.Util.wixext `
    -d "Version=$version" `
    -d "AgentExe=$exe" `
    -o $out
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Write-Output $out
