###
## Copyright © 2022, GoSecure, Inc. – All Rights Reserved
## 
## This code is confidential GoSecure, Inc. property.  This software and its code
## may only be used by GoSecure, Inc. for internal business purposes.
## For more information consult the GoSecure, Inc. Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Module functions for domain controller certificate deployment scripts
##
###
## NOTE: Use of this module requires that the Remote Server Administraton Tools (RSAT)
## for Windows feature is installed on the system you're running from, so the 
## ActiveDirectory module is available.
##
## Author: kmontgomery@gosecure.net
## Date: 2022-04-13
###


#Requires -Version 4.0
#Requires -Modules ActiveDirectory

$CachedDCList = $null

##
# Function to get domain controllers from environment.
##
function Get-DomainControllers {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false)]
    [Boolean] $NoCache = $false,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false)]
    [Boolean] $StripDomain = $false
  )

  if ($CachedDCList -And !$NoCache) {
    if ($CachedDCList) { Write-Verbose "INFO: Not using cached list."; }
    Write-Verbose "INFO: List size: $($CachedDCList.Length)"
    ,$CachedDCList | Format-DCList -Verbose:($PSBoundParameters['Verbose'] -eq $true) -StripDomain $StripDomain
    return
  }

  $DomainName = (Get-ADDomain).DNSRoot
  $DCList = Get-ADDomainController -Filter * -Server $DomainName | Select-Object -ExpandProperty Hostname
  if (!$NoCache -And $DCList.Length -gt 0) {
    Write-Verbose "INFO: Caching results..."
    $CachedDCList = $DCList;
  }
  Write-Verbose "INFO: List size: $($DCList.Length)"
  ,$DCList | Format-DCList -Verbose:($PSBoundParameters['Verbose'] -eq $true) -StripDomain $StripDomain
}

##
# Format the Domain Controller List Output
##
function Format-DCList {
  [CmdletBinding()]
  param(
    [Parameter(ValueFromPipeline,Mandatory)]
    [object[]]$OutputList,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false)]
    [Boolean] $StripDomain = $false
  )
  if ($StripDomain) {
    Write-Verbose "INFO: Output: $($OutputList.Length)"
    $OutputList | Foreach-Object { $_ -replace '\..*$','' }
    return
  }
  Write-Verbose "INFO: Output: $($OutputList.Length)"
  $OutputList
}

##
# Generate a new cert_gen_config.psd1 (by default) configuration file.
##
function New-CertGenConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false)]
    [string] $ConfigFileName = "cert_gen_config.psd1",
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false)]
    [boolean] $Overwrite = $false,
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,ValueFromPipeline=$false)]
    [boolean] $StripDomain = $true
  )

  $ConfigFullPath="$PSScriptRoot\$ConfigFileName"

  if (Test-Path $ConfigFullPath) {
    Write-Verbose "INFO: $ConfigFullPath exists..."
    if (!$Overwrite) {
      # Write-Error "$ConfigFullPath exists."
      throw [System.IO.IOException] "$ConfigFullPath already exists"
    }
  }

  $CertClients = Get-DomainControllers -StripDomain $StripDomain
  $ShareUsers = @(
    "$($Env:UserDomain)\$($Env:UserName)"
    "$($Env:UserDomain)\Domain Admins"
  )
  
  $CertClients = '"{0}"' -f ($CertClients -join '","')
  $ShareUsers = '"{0}"' -f ($ShareUsers -join '","')
  Write-Output @"
@{
  CertificateClients = @($CertClients)
  CertsShareUsers = @($ShareUsers)
}
"@ | Out-File $ConfigFullPath -Encoding utf8 -Force    
}


Export-ModuleMember -function Get-DomainControllers
Export-ModuleMember -function New-CertGenConfig
