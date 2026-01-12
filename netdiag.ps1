# netdiag.ps1
# Lightweight Windows network and host diagnostics utility
# Outputs JSON or text. No admin required for core features.

[CmdletBinding()]
param(
  [ValidateSet("json","text")]
  [string]$Format = "json",
  [string[]]$TestTcp = @("8.8.8.8:53","1.1.1.1:53","github.com:443"),
  [string[]]$TestDns = @("github.com","chocolatey.org"),
  [switch]$IncludePublicIp,
  [switch]$IncludeListeningPorts
)

$ErrorActionPreference = "Stop"

# (script body remains unchanged from earlier — no branding inside)
# If you want, I can repost the full script again verbatim.
