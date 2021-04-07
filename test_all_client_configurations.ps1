###
## Copyright © 2021, Columbus Collaboratory LLC d/b/a Covail™ – All Rights Reserved
## 
## This code is confidential Covail™ property.  This software and its code
## may only be used by Covail™ for internal business purposes.
## For more information consult the Covail™ Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Configure Windows Event Forwarding Policy
##
## Author: kmontgomery@covail.com
## Date: 2021-03-26
###

#Requires -Version 4.0

[CmdletBinding()]
param()

if ((Get-Host).Version.Major -lt 5) {
  Import-LocalizedData -BindingVariable Cfg -BaseDirectory $PSScriptRoot -FileName cert_gen_config.psd1
} 
else {
  $Cfg = Import-PowerShellDataFile $PSScriptRoot\cert_gen_config.psd1
}

if (!$Cfg -or !$Cfg.CertificateClients) {
  throw "Configuration not found!"
}

Write-Verbose "Configuration found!"

if ((Get-Host).Version.Major -lt 5) {
  Import-LocalizedData -BindingVariable config -BaseDirectory $PSScriptRoot -FileName atdp_subscription_data.psd1
} 
else {
  $config = Import-PowerShellDataFile $PSScriptRoot\atdp_subscription_data.psd1
}

if (!$config -or !$config.WEC_Server_FQDN -or !$config.Auth_Certificate_Issuer_CA_Thumbprint) {
  Import-Module -Name (Join-Path $PSScriptRoot event_forwarding_module_functions.psm1 -Resolve) -WarningAction SilentlyContinue
  Write-Host "The subscription configuration must be completed before test can proceed...."
  Configure-ScriptData
}

$Cfg.CertificateClients | Foreach-Object {
  try {
    $Error.clear()
    $remote_module_path = "\\$_\c$\Windows\Temp"
    Copy-Item -Path $PSScriptRoot\event_forwarding_module_functions.psm1 -Destination "${remote_module_path}\event_forwarding_module_functions.psm1"
    Copy-Item -Path $PSScriptRoot\atdp_subscription_data.psd1 -Destination "${remote_module_path}\atdp_subscription_data.psd1"
    $session = New-PSSession -ComputerName $_
    Write-Host "INFO: Running test on host $_..."
    $verbOut = if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) { $true } else { $false }
    Write-Host "Verbosity enabled: "$verbOut""
    Invoke-Command -Session $session -ScriptBlock {
      Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
      Import-Module -Name (Join-Path "C:\Windows\Temp" event_forwarding_module_functions.psm1) -WarningAction SilentlyContinue
      if (! (Test-LocalWinRMConfiguration -Verbose:$Using:verbOut)) {
        Write-Warning "$Using:_ did not test clean."
      }
      else {
        Write-Host "$Using:_ configuration was ok for windows event forwarding, testing WEC connectivity..."
        (Get-WecConfiguration -Verbose:$Using:verbOut).Service | Format-Custom -Depth 3
      }
    }

    Write-Verbose "Cleaning up module and configuration files on $_..."
    Remove-Item -Path "${remote_module_path}\event_forwarding_module_functions.psm1"
    Remove-Item -Path "${remote_module_path}\atdp_subscription_data.psd1"
    Write-Host
  }
  catch {
    Write-Error "$($Error[-1].Exception.Message)"
  }
  finally {
    if ($session) {
      Write-Verbose "INFO: removing session for $_..."
      REmove-PSSession -Session $session
    }
  }

}