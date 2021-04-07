###
## Copyright © 2021, Columbus Collaboratory LLC d/b/a Covail™ – All Rights Reserved
## 
## This code is confidential Covail™ property.  This software and its code
## may only be used by Covail™ for internal business purposes.
## For more information consult the Covail™ Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Import Local Machine Client Authentication Certificate
##
## Author: kmontgomery@covail.com
## Date: 2021-02-15
###

#Requires -Version 4.0

# Check for HOSTNAME Variable
($hostobj = Get-WmiObject -Class Win32_ComputerSystem) 2>$null | out-null

if (!$hostobj) {
  $host.ui.WriteErrorLine("ERROR: could not get computername from WMI.")
  exit 1
}

$hostname = "$($hostobj.Name).$($hostobj.Domain)"

# Certificate file path
$cert_file = "$PSScriptRoot\$hostname.cer"
$root_cert_file = "$PSScriptRoot\root-ca.cer"
$intermediate_cert_file = "$PSScriptRoot\intermediate-ca.cer"

if (![System.IO.File]::Exists($cert_file)) {
  $host.ui.WriteErrorLine("ERROR: certificate file not found at $cert_file.")
  exit 1
}

if (![System.IO.File]::Exists($root_cert_file)) {
  $host.ui.WriteErrorLine("ERROR: No Root CA file found at $root_cert_file, cannot import Root CA.")
  exit 1
}

Write-Host "INFO: Importing Root CA Certificate from $root_cert_file."
Import-Certificate -FilePath $root_cert_file -CertStoreLocation cert:\LocalMachine\Root

if (![System.IO.File]::Exists($intermediate_cert_file)) {
  Write-Warning "ERROR: No Intermediate CA file found at $intermediate_cert_file, cannot import Intermediate CA."
}
else {
  Write-Host "INFO: Importing Intermediate CA Certificate from $intermediate_cert_file."
  Import-Certificate -FilePath $intermediate_cert_file -CertStoreLocation cert:\LocalMachine\CA
}

Write-Host "INFO: Importing certificate for $hostname"
$cert = Import-Certificate -FilePath $cert_file -CertStoreLocation cert:\LocalMachine\My
$importStatus = $LASTEXITCODE
Write-Host "INFO: import exit code = $importStatus"
if ($cert.Thumbprint) {
  $thumbprint = $cert.Thumbprint.ToLower() 
  Write-Host "INFO: Certifidate thumbprint $thumbprint"
}
else {
  Write-Warning "WARN: NO certificate thumbprint - import may have failed!"
}