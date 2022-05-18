###
## Copyright © 2021, Columbus Collaboratory LLC d/b/a Covail™ – All Rights Reserved
## 
## This code is confidential Covail™ property.  This software and its code
## may only be used by Covail™ for internal business purposes.
## For more information consult the Covail™ Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Remove ATDP's Local Machine Client Authentication Certificate And Issuer Chain on all ATDP Domain Controllers (by configuration)
## NOTE: This does not work since it can't prompt the user for input on remote systems
##
## Author: kmontgomery@covail.com
## Date: 2021-06-21
###

#Requires -Version 4.0

# Check for the client list configuration
if (! (Test-Path -Path $PSScriptRoot\cert_gen_config.psd1)) {
  Write-Error "ERROR: there is no cert_gen_config.psd1 file listing the computers to generate certificare requests for."
  exit 1
}

if ((Get-Host).Version.Major -lt 5) {
  Import-LocalizedData -BindingVariable Config -BaseDirectory $PSScriptRoot -FileName cert_gen_config.psd1
} 
else {
  $Config = Import-PowerShellDataFile $PSScriptRoot\cert_gen_config.psd1
}

$upath = "Windows\Temp"

if (! (Test-Path -Path $PSScriptRoot\remove_atdp_certs.ps1 -PathType leaf)) {
  Write-Error "ERROR: no remove_atdp_certs.ps1 file, client script requests can not be created."
  exit 2
}

# Loop over the list of computers and create a certificate reqeuest for each, then copy it back to 
# the new "certs" share
foreach ($Computer in $Config.CertificateClients) {
  try {
    Write-Host "Copying cert script from $PSScriptRoot\remove_atdp_certs.ps1 to \\$Computer\c$\$upath\certreq..."
    (New-Item -Path \\$Computer\c$\$upath -Name "certreq" -ItemType "directory" 2> $null) | out-null
    Copy-Item -Path $PSScriptRoot\remove_atdp_certs.ps1 -Destination \\$Computer\c$\$upath\certreq\
    Invoke-Command -ComputerName $Computer -ScriptBlock {
      powershell -ExecutionPolicy bypass -File C:\$Using:upath\certreq\remove_atdp_certs.ps1 -Verbose
    } 2>$null
  }
  catch {
    Write-Host "$($computer) " -BackgroundColor red -NoNewline
    Write-Warning $Error[0] 
  }
}