# Generates an unsigned .NET Framework launcher in this staging directory.
# Review and code-sign through enterprise release tooling. Does not edit policies.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
$here = $PSScriptRoot
$settings = Get-Content -LiteralPath (Join-Path $here 'launcher-settings.json') -Raw | ConvertFrom-Json
$source = Get-Content -LiteralPath (Join-Path $here 'windows-launcher.cs') -Raw
foreach ($field in @('node', 'host', 'config')) {
    $value = [string]$settings.$field
    if (-not [System.IO.Path]::IsPathRooted($value) -or -not (Test-Path -LiteralPath $value -PathType Leaf)) { throw 'PATH_INVALID' }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))
    $source = $source.Replace('__' + $field.ToUpperInvariant() + '_BASE64__', $encoded)
}
$output = Join-Path $here 'aidr-native-launcher.exe'
if (Test-Path -LiteralPath $output) { throw 'OUTPUT_EXISTS' }
Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly $output -OutputType ConsoleApplication
Write-Output 'Unsigned launcher built. Perform Windows runtime tests and enterprise code signing before registration.'
