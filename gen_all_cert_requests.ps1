###
## Copyright © 2022, GoSecure, Inc. – All Rights Reserved
## 
## This code is confidential GoSecure, Inc. property.  This software and its code
## may only be used by GoSecure, Inc. for internal business purposes.
## For more information consult the GoSecure, Inc. Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Create Client Certificate Requests for a Configured List of Clients
##
## Author: kmontgomery@gosecure.net
## Date: 2022-04-13
###

###
## Prerequisites:
## 1) permissions by the user running this script to create a C:\certs directory on the windows server it is run from
##    and add share permissions to it; this share will be used to copy cert requests and certificates back and forth
##    to the client certificate target systems (should run this script using an elevated permission shell)
## 2) cert_gen_config.psd1 file in the directory this script runs from, listing the computers to generate certs for
##    and a list of users to give permissions to the certs share (could just be your user); NOTE: as of 2022-04, the
##    script will generate this configuration
###

#Requires -Version 4.0
#Requires -Modules ActiveDirectory

# Check for the client list configuration
if (! (Test-Path -Path $PSScriptRoot\cert_gen_config.psd1)) {
  Import-Module -Name (Join-Path $PSScriptRoot cert_functions.psm1 -Resolve) -WarningAction SilentlyContinue
  Write-Host "INFO: There is no configuration file, building a default configuration with domain controllers as the target systems for certificate generation."
  New-CertGenConfig -Verbose:($PSBoundParameters['Verbose'] -eq $true) -Overwrite $false
}

if ((Get-Host).Version.Major -lt 5) {
  Import-LocalizedData -BindingVariable Config -BaseDirectory $PSScriptRoot -FileName cert_gen_config.psd1
} 
else {
  $Config = Import-PowerShellDataFile $PSScriptRoot\cert_gen_config.psd1
}

$upath = "Windows\Temp"
($hostobj = Get-WmiObject -Class Win32_ComputerSystem) 2>$null | out-null

if (! (Test-Path -Path $PSScriptRoot\gen_client_csr.ps1 -PathType leaf)) {
  Write-Error "ERROR: no gen_client_csr.ps1 file, client script requests can not be created."
  exit 2
}

# On the computer that is running this script, create a "certs" directory and share
# to be the location to copy requests and certificates to and from
if (! (Test-Path -Path C:\certs)) {
  [SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', Scope='member')]
  $certdir = New-Item -Path C:\ -Name "certs" -ItemType "directory"
}

if (! (Get-SmbShare -Name "certs") 2>$null) {
    Write-Host "INFO: Configurinng certs share with access for $($Config.CertsShareUsers)..."
    $newShare = New-SmbShare -Name "certs" -Path "C:\certs" -FullAccess $($Config.CertsShareUsers)
    if ($null -eq $newShare) {
      Write-Error "ERROR: Could not create certs share"
      exit 2
    }
}

# Loop over the list of computers and create a certificate reqeuest for each, then copy it back to 
# the new "certs" share
foreach ($Computer in $Config.CertificateClients) {
  try {
    if (! (Test-Path -Path "\\$Computer\c$\$upath\certreq")) {
      $crPath = New-Item -Path \\$Computer\c$\$upath -Name "certreq" -ItemType "directory"
      if ($null -eq $crPath) {
        Write-Error "ERROR: could not create certreq directory on $Computer; skipping..."
        continue
      }
    }
    Write-Host "Copying cert script from $PSScriptRoot\gen_client_csr.ps1 to \\$Computer\c$\$upath\certreq..."
    Copy-Item -Path $PSScriptRoot\gen_client_csr.ps1 -Destination \\$Computer\c$\$upath\certreq\
    Invoke-Command -ComputerName $Computer -ScriptBlock {
      ## Autolab Specific -- remove the VirtualLab certificates from the cert store
      # Write-Host "Removing any VirtualLab* certificates.."
      # Get-ChildItem Cert:\\LocalMachine\My | Where-Object {$_.Subject -Match "^CN=Virtual.*"} | Remove-Item
      Write-Host "Running client cert request generator..."
      powershell -ExecutionPolicy bypass -File C:\$Using:upath\certreq\gen_client_csr.ps1
    } 2>$null
  }
  catch {
    Write-Host "$($computer) " -BackgroundColor red -NoNewline
    Write-Warning $Error[0] 
  }

  # Check for, and copy the certificate request back to the "certs" share.
  $reqPath = "\\$Computer\c$\$upath\certreq\"
  Write-Host "Looking for $reqpath..."
  if (Test-Path -Path $reqPath) {
    Write-Host "Copying $reqPath .req file(s)..."
    $files = @(Get-ChildItem $reqPath -Filter "$Computer.$($hostobj.Domain).req")
    if ($files.Length -eq 0) {
      Write-Warning "ERROR: No $($reqPath)\$($Computer).$($hostobj.Domain) found"
    }
    else {
      Write-Host "Copying $($reqPath)\$($Computer).$($hostobj.Domain) file..."
      $files | Copy-Item -Destination \\$($hostobj.Name)\certs\
    }
  }
  else {
    Write-Warning "ERROR: No $reqPath found"
  }
}
