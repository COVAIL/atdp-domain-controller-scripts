###
## Copyright © 2021, Columbus Collaboratory LLC d/b/a Covail™ – All Rights Reserved
## 
## This code is confidential Covail™ property.  This software and its code
## may only be used by Covail™ for internal business purposes.
## For more information consult the Covail™ Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Create Certificate Request
##
## Author: kmontgomery@covail.com
## Date: 2021-02-15
###

# Check for HOSTNAME Variable
($hostobj = Get-WmiObject -Class Win32_ComputerSystem) 2>$null | out-null

if (!$hostobj) {
  $host.ui.WriteErrorLine("ERROR: could not get computername from WMI.")
  exit 1
}

$hostname = "$($hostobj.Name).$($hostobj.Domain)"

# Request file path
$req_file = "$PSScriptRoot\$hostname.req"

$Windows ='$Windows'
$request_string = @"
[Version]
Signature="$Windows NT$"

[Strings]
szOID_ENHANCED_KEY_USAGE = "2.5.29.37"
szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

[NewRequest]
FriendlyName = "$hostname WEC Client Cert"
Subject = "CN=$hostname"
Exportable = TRUE
MachineKeySet = TRUE
HashAlgorithm = sha256
KeyLength = 2048
KeyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE|CERT_KEY_ENCIPHERMENT_KEY_USAGE
KeyUsageProperty = NCRYPT_ALLOW_DECRYPT_FLAG|NCRYPT_ALLOW_SIGNING_FLAG
RequestType = PKCS10
SecurityDescriptor = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;NS)"

[Extensions]
2.5.29.17 = "{text}DNS=$hostname"
%szOID_ENHANCED_KEY_USAGE% = "{text}1.3.6.1.5.5.7.3.2"
"@

# Write out the request .inf file
echo "$request_string" | Out-File -FilePath "$req_file.inf"

Write-Host "INFO: Generating certificate request from $req_file.inf and saving the result in $req_file"

# Write-Host "" | Out-File -FilePath $req_file
certreq -new -q -f -machine "$req_file.inf" "$req_file"
$certReqStatus = $LASTEXITCODE

if ($certReqStatus -eq 0) {
  Write-Host "INFO: Success ($hostname)."
}
else {
  $host.ui.WriteErrorLine("ERROR: certificate request failed.")
  exit 1
}
