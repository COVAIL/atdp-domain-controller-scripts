###
## Copyright © 2022, GoSecure, Inc. – All Rights Reserved
## 
## This code is confidential GoSecure, Inc. property.  This software and its code
## may only be used by GoSecure, Inc. for internal business purposes.
## For more information consult the GoSecure, Inc. Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Test connectivity from current workstation to certificate "client" computers.
##
###
##
## Author: kmontgomery@gosecure.net
## Date: 2022-04-14
###

#Requires -Version 4.0

[CmdletBinding()]
param()

Import-Module -Name (Join-Path $PSScriptRoot cert_functions.psm1 -Resolve) -WarningAction SilentlyContinue

try {
  New-CertGenConfig -Verbose:($PSBoundParameters['Verbose'] -eq $true) -Overwrite $false
}
catch {}


if ((Get-Host).Version.Major -lt 5) {
  Import-LocalizedData -BindingVariable Config -BaseDirectory $PSScriptRoot -FileName cert_gen_config.psd1
} 
else {
  $Config = Import-PowerShellDataFile $PSScriptRoot\cert_gen_config.psd1
}

foreach ($Computer in $Config.CertificateClients) {
  try {
    Write-Host "INFO: Testing running a command on $Computer..."
    $r = Test-WSMan -ComputerName $Computer 2>$null

    if (! $r) {
      Write-Host "Error: No conection to $Computer" -BackgroundColor red
    }
    else {
      Write-Host "INFO: Connection to $Computer success!" -BackgroundColor green
    }
    # $r = Invoke-Command -ComputerName $Computer -ScriptBlock {
    #     Write-Output "INFO: Running on $Env:ComputerName"
    #     #powershell -ExecutionPolicy bypass -File C:\$Using:upath\certreq\gen_client_csr.ps1
    # } 2>$null
    # if (! $r) {
    #   Write-Host "ERROR: $Computer didn't return output" -BackgroundColor red
    # }
    # else {
    #   Write-Host $r -BackgroundColor green
    # }
  }
  catch {
    Write-Host "$($computer) " -BackgroundColor yellow -NoNewline
    Write-Warning $Error[0] 
  }
}
