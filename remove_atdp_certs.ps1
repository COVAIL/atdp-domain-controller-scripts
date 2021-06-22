###
## Copyright © 2021, Columbus Collaboratory LLC d/b/a Covail™ – All Rights Reserved
## 
## This code is confidential Covail™ property.  This software and its code
## may only be used by Covail™ for internal business purposes.
## For more information consult the Covail™ Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Remove ATDP's Local Machine Client Authentication Certificate And Issuer Chain
##
## Author: kmontgomery@covail.com
## Date: 2021-06-21
###

#Requires -Version 4.0

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
  [string]$IssuerThumbprint
)

# Check for HOSTNAME Variable
($hostobj = Get-WmiObject -Class Win32_ComputerSystem) 2>$null | out-null

if (!$hostobj) {
  $host.ui.WriteErrorLine("ERROR: could not get computername from WMI.")
  exit 1
}

$hostname = "$($hostobj.Name).$($hostobj.Domain)"

function Remove-AtpdCertChain {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
    [string]$IssuerThumbprint = $null
  )

  # Attempt to look up certs using FriendlyName First...
  $atdpCerts = Get-ChildItem -path cert:\LocalMachine\My | Where-Object { $_.FriendlyName -Like "*WEC Client Cert" -And $_.Subject -eq "CN=$($hostname)" }

  if ($atdpCerts) {
    Write-Verbose "Found $($atdpCerts.Length) ATDP certs to remove..."
    $atdpCerts | %{
      $_ | Format-Table -Property Subject,Issuer
      $decision = $Host.UI.PromptForChoice('Remove Cert?', "Remove the $($_.Subject) certificate (and it's chain)?", ('&yes','&no'), 1)
      if ($decision -eq 0) {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        Write-Verbose "Building cert chain for $($_.Subject)..."
        $chain.Build($_) | out-null
        Write-Verbose "Found $($chain.ChainElements.Count) elements to remove..."
        $chain.ChainElements.Certificate | %{
          Write-Host "Removing certificate $($_.Subject) / $($_.Thumbprint)..."
          $thumb = $_.Thumbprint
          Get-ChildItem -path "cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq "$thumb"} | Remove-Item
          Get-ChildItem -path "cert:\LocalMachine\CA" | Where-Object { $_.Thumbprint -eq "$thumb"} | Remove-Item
          Get-ChildItem -path "cert:\LocalMachine\Root" | Where-Object { $_.Thumbprint -eq "$thumb"} | Remove-Item
        }
      }
    }
  }
  else {
    $decision =  $Host.UI.PromptForChoice('Continue?', "We didn't automatically find an ATDP certificate, would you like to loop through any ohter client certificates to check for them?", ('&yes','&no'), 1)
    if ($decision -eq 0) {
      $allClientCerts = ( Get-ChildItem -path cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList -Like "*Client Authentication*"} )
      if (! $allClientCerts) {
        continue
      }
      $allClientCerts | %{
        $_ | Format-Table -Property Subject,Issuer
        $decision = $Host.UI.PromptForChoice('Remove Cert?', "Remove the $($_.Subject) certificate (and it's chain)?", ('&yes','&no'), 1)
        if ($decision -eq 0) {
          $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
          Write-Verbose "Building cert chain for $($_.Subject)..."
          $chain.Build($_) | out-null
          Write-Verbose "Found $($chain.ChainElements.Count) elements to remove..."
          $chain.ChainElements.Certificate | %{
            Write-Host "Removing certificate $($_.Subject) / $($_.Thumbprint)..."
            $thumb = $_.Thumbprint
            Get-ChildItem -path "cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq "$thumb"} | Remove-Item
            Get-ChildItem -path "cert:\LocalMachine\CA" | Where-Object { $_.Thumbprint -eq "$thumb"} | Remove-Item
            Get-ChildItem -path "cert:\LocalMachine\Root" | Where-Object { $_.Thumbprint -eq "$thumb"} | Remove-Item
          }
        }
      }
    }
    else {
      Write-Host "Ok, we're finished."
    }
  }
}

# Run the remove function
Write-Verbose "Attempting to remove ATDP certificates..."
Remove-AtpdCertChain -IssuerThumbprint $IssuerThumbprint