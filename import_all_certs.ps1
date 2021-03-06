###
## Copyright © 2022, GoSecure, Inc. – All Rights Reserved
## 
## This code is confidential GoSecure, Inc. property.  This software and its code
## may only be used by GoSecure, Inc. for internal business purposes.
## For more information consult the GoSecure, Inc. Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Import Local Machine Client Authentication Certificates for a List Of Clients
##
## Author: kmontgomery@gosecure.net
## Date: 2021-02-15
###

###
## Prerequisites:
## 1) cert_gen_config.psd1 file in the directory this script runs from, listing the computers to generate certs for
##    and a list of users to give permissions to the certs share (could just be your user)
## 2) the root and any intermediate ca certificates, located in the "certs" share as root-ca.cer and intermediate-ca.cer
##    respectively
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
($hostobj = Get-WmiObject -Class Win32_ComputerSystem) 2>$null | out-null

if (! (Test-Path -Path $PSScriptRoot\import_client_cert.ps1 -PathType leaf)) {
  Write-Error "ERROR: no import_client_cert.ps1 file, client script requests cannot be imported."
  exit 2
}

# Check for "certs" share
if (! (Test-Path \\$($hostobj.Name)\certs)) {
  Write-Error "ERROR: No share \\$($hostobj.Name)\certs, cannot continue."
  exit 2
}

# Check for intermediate-ca.cer and root-ca.cer existence
if (! ((Test-Path -Path \\$($hostobj.Name)\certs\root-ca.cer -PathType leaf) -and (Test-Path -Path \\$($hostobj.Name)\certs\intermediate-ca.cer -PathType leaf))) {
  Write-Error "ERROR: Missing root-ca.cer or intermediate-ca.cer in \\$($hostobj.Name)\certs, cannot continue."
  exit 2
}

# Loop over the list of computers and import the client cert for each from the "certs" share
foreach ($Computer in $Config.CertificateClients) {
  $certPath = "\\$Computer\c$\$upath\certreq\$Computer.$($hostobj.Domain).cer"
  Write-Host "Copying import script and ca certs from $PSScriptRoot to \\$Computer\c$\$upath\certreq\..."
  Copy-Item -Path $PSScriptRoot\import_client_cert.ps1 -Destination \\$Computer\c$\$upath\certreq\
  Write-Host "Copying ca certs from \\$($hostobj.Name)\certs\ to \\$Computer\c$\$upath\certreq\..."
  Copy-Item -Path \\$($hostobj.Name)\certs\root-ca.cer -Destination \\$Computer\c$\$upath\certreq\
  Copy-Item -Path \\$($hostobj.Name)\certs\intermediate-ca.cer -Destination \\$Computer\c$\$upath\certreq\
  $certSourcePath = "\\$($hostobj.Name)\certs\$Computer.$($hostobj.Domain).cer"
  Write-Host "Looking for $certSourcePath..."
  if (Test-Path -Path $certSourcePath -PathType leaf) {
    Write-Host "Copying $certSourcePath to $certPath..."
    Copy-Item -Path $certSourcePath -Destination $certPath
    try {
      Invoke-Command -ComputerName $Computer -ScriptBlock {
        powershell -ExecutionPolicy bypass -File C:\$Using:upath\certreq\import_client_cert.ps1
        Get-ChildItem -Path Cert:\LocalMachine\My | Format-Table Thumbprint,Subject -AutoSize 
      } 2>$null
    }
    catch {
      Write-Host "$($computer) " -BackgroundColor red -NoNewline
      Write-Warning $Error[0] 
    }
  }
  else {
    Write-Warning "ERROR: No $certPath found"
  }
}

($share = Get-SmbShare -Name "certs") | Out-Null

if ($share) {
  $answer = $null
  do {
    # Ask the user if they would like to remove the "certs" share now...
    $answer = Read-Host -Prompt "Would you like to remove the 'certs' share? (yes/no)"
    if ($answer) {
      if ($answer.ToUpper() -eq "Y" -or $answer.ToUpper() -eq "YES") {
        Write-Host "INFO: removing 'certs' share..."
        Remove-SmbShare -Name "certs" -Force
      }
      else {
        Write-Host "Ok, the 'certs' share will be left. Please remove the share when you are finished configuring certificates."
      }
    }
  } while (! $answer)
}