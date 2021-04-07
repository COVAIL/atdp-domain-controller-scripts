###
## Copyright © 2021, Columbus Collaboratory LLC d/b/a Covail™ – All Rights Reserved
## 
## This code is confidential Covail™ property.  This software and its code
## may only be used by Covail™ for internal business purposes.
## For more information consult the Covail™ Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Module functions for configure_windows_event_formwarding.ps1 script
##
## Author: kmontgomery@covail.com
## Date: 2021-03-26
###

#Requires -Version 4.0

$domain_controller_policy_name = "ATDP_WindowsEventForwarding_DomainControllers"
$subscription_manager_policy_key = "HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
$security_event_log_sd_key = "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security"
($hostobj = Get-WmiObject -Class Win32_ComputerSystem) 2>$null | out-null

function Configure-DomainControllerEventFowarding {
  [CmdletBinding()]
  [OutputType([Boolean])]
  param()

  $dc_policy = (Get-Gpo -name $domain_controller_policy_name) 2>$null

  if (! $dc_policy) {
    Write-Host "INFO: Policy ${domain_controller_policy_name} does not yet exist, creating new policy..."
    # Clear the error variable so we can tell if the next command fails or not.
    $Error.Clear()
    ($dc_policy = New-Gpo -Name "${domain_controller_policy_name}" -Comment 'Windows Event Forwarding Policy for Domain Controllers for the COVAIL Attack Detector Platform') | Out-Null
    if ($Error.Count -gt 0) {
      $m = $Error[-1].Exception.Message
      Write-Error "ERROR: Could not create policy ${domain_controller_policy_name}: ${m}."
      return $false
    }
  }
  else {
    Write-Host "INFO: Policy ${domain_controller_policy_name} exists!"
  }

  ($subscription_manager_policy = Get-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$subscription_manager_policy_key" 2>$null) | Out-Null

  $Config = Get-ScriptData

  # $issuer_ca_thumbprint = (Get-ChildItem -Path cert:\LocalMachine\CA | Where-Object { $_.Subject -Match "CN=AtdpLab2-Root" } | ForEach-Object {$_.Thumbprint.ToLower()})
  # $domain_name = (Get-WmiObject Win32_ComputerSystem).Domain

  if (! $subscription_manager_policy) {
    Write-Host "INFO: Configuring WEF Subscritpion Manager Policy..."
    $subscription = "Server=HTTPS://$($Config.WEC_Server_FQDN):5986/wsman/SubscriptionManager/WEC,Refresh=60,IssuerCA=$($Config.Auth_Certificate_Issuer_CA_Thumbprint)"
    Write-Verbose "Subscription: ${subscription}"
    ($subscription_manager_policy = Set-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$subscription_manager_policy_key" -ValueName "1" -Type String -Value "${subscription}") | Out-Null
  } else {
    Write-Host "INFO: Subscription is currently set to: $($subscription_manager_policy.Value)"
  }

  # Configure security descriptor to allow NetworkService access to the Security Event Log

  ($security_event_log_sd_policy = Get-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$security_event_log_sd_key" 2>$null) | Out-Null
  if (! $security_event_log_sd_policy) {
    Write-Host "INFO: Configuring WEF Security Event Log SDDC Policy..."
    $value = "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)"
    ($security_event_log_sd_policy = Set-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$security_event_log_sd_key" -ValueName "ChannelAccess" -Type String -Value "${value}") | Out-Null
  } else {
    Write-Host "INFO: Security log SDDC already set to $($security_event_log_sd_policy.Value)"
  }

  # Ensure GPO is linked to Domain Controllers...
  $ou = "ou=Domain Controllers,dc=$($hostobj.Domain.replace('.',',dc='))"

  # Check for link
  $LinkCount = (((Get-GPInheritance -Target "${ou}").GpoLinks | Where-Object { $_.DisplayName -eq "$domain_controller_policy_name" }).Length)

  if ($LinkCount -lt 1) {
    try {
      Write-Host "INFO: linking ${domain_controller_policy_name} to ${ou}..."
      ($link = New-GPLink -Name "$domain_controller_policy_name" -Target "${ou}" -Enforced Yes) | Out-Null
    }
    catch {
      Write-Error "Could not create GPO Link: $_"
    }
  } else {
    Write-Host "INFO: ${domain_controller_policy_name} is already linked at ${ou}.."
  }

  return $true
}


function Get-ScriptData {
  if (! ((Test-Path -Path $PSScriptRoot\atdp_subscription_data.psd1) 2>$null) -eq $true) {
    Write-Warning "WARN: No susbscription configuration data exists, please follow the prompts to provide the required information..."
    $null = Configure-ScriptData
  }

  if ((Get-Host).Version.Major -lt 5) {
    Import-LocalizedData -BindingVariable Config -BaseDirectory $PSScriptRoot -FileName atdp_subscription_data.psd1
  } 
  else {
    $Config = Import-PowerShellDataFile $PSScriptRoot\atdp_subscription_data.psd1
  }
  return $Config
}

function Configure-ScriptData {
  [CmdletBinding()]
  [OutputType([Boolean])]
  param()

  $Config = Get-ScriptData
  
  if (! $Config) {
    $Config = @{}
  }

  # Prompt for WEC Hostname
  do {
    $default_val = $Config.WEC_Server_FQDN
    $default_str = if ($default_val) { " (default: ${default_val})" } else { "" }
    $user_input = Read-Host -Prompt "Please provide the WEC hostname that was provided by COVAIL${default_str}"
    if ([string]::IsNullOrEmpty($user_input)) { $user_input = $default_val }
  } while ([string]::IsNullOrEmpty($user_input))

  $Config['WEC_Server_FQDN'] = $user_input
  Write-Verbose "WEC_HOSTNAME = $($Config.WEC_Server_FQDN)"
  $user_input = $null

  # Read in system CA thumbprint(s)
  $Thumbprints = @()

  Get-ChildItem -path cert:\LocalMachine\CA | ForEach-Object { $Thumbprints += @{ Subject=$_.Subject; Thumbprint=$_.Thumbprint } }

  # Prompt for Issuer Thumbprint
  do {
    # $default_val = $Config.Auth_Certificate_Issuer_CA_Thumbprint
    $prompt = "System CA Certificates:`n"
    foreach ($item in $Thumbprints)
    {
      $prompt += "$($Thumbprints.IndexOf($item)): $($item.Subject)`n"
      if ($Config.Auth_Certificate_Issuer_CA_Thumbprint -eq $item.Thumbprint) {
        $default_val = $Thumbprints.IndexOf($item)
      }
    }
    $default_str = if ($default_val) { " (default: ${default_val})" } else { "" }
    $prompt += "Please select the Issuer CA Thumbprint's number from above to use for authentication certificate(s)${default_str}"
    $user_input = Read-Host -Prompt "$prompt"
    if ([string]::IsNullOrEmpty($user_input)) {
      try {
        $user_input = $Thumbprints[$default_val].Thumbprint
      }
      catch {
        $user_input = $null
      }
    }
    else {
      try {
        $user_input = $Thumbprints[$user_input].Thumbprint
      }
      catch {
        $user_input = $null
      }
    }
  } while ([string]::IsNullOrEmpty($user_input))

  $Config['Auth_Certificate_Issuer_CA_Thumbprint'] = $user_input
  Write-Verbose "Thumbprint = $($Config.Auth_Certificate_Issuer_CA_Thumbprint)"

  Write-Output @"
@{
  WEC_Server_FQDN = "$($Config.WEC_Server_FQDN)"
  Auth_Certificate_Issuer_CA_Thumbprint = "$($Config.Auth_Certificate_Issuer_CA_Thumbprint)"
}
"@ | Out-File $PSScriptRoot\atdp_subscription_data.psd1 -Encoding utf8 -Force

  return $true
}

function Get-WecConfiguration {
  [CmdletBinding()]
  [OutputType([Object])]
  param()

  $Config = Get-ScriptData
  
  if (!$Config.Auth_Certificate_Issuer_CA_Thumbprint) {
      Write-Error "Issuer thumbprint configuration not found, cannot continue."
      throw "Expected Conditions Not Met"
  }
  
  $IssuerCert = (Get-ChildItem -Path cert:\LocalMachine\CA | Where-Object { $_.Thumbprint -eq "$($Config.Auth_Certificate_Issuer_CA_Thumbprint)"} | Select-Object -First 1)
  
  if (!$IssuerCert) {
      Write-Error "Could not find issuer certificate with thumbprint $($Config.Auth_Certificate_Issuer_CA_Thumbprint) in the machine's intermediate CA store, cannot continue."
      throw "Expected Conditions Not Met"
  }
  
  $AuthCertificate = (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.Subject -Like "CN=$($hostobj.Name).$($hostobj.Domain)" -And $_.Issuer -eq "$($IssuerCert.Subject)" } | Select-Object -First 1)
  
  # Get local config so we can check to make sure settings are as we expect on the client side (certificate auth enabled, etc.)
  #$WinRMConfig = Get-WSManInstance winrm/config
  
  if (!$Config.WEC_Server_FQDN) {
      Write-Error "WEC hostname not configured, cannot continue."
      throw "Expected Conditions Not Met"
  }
  
  Write-Verbose "Checking configuration on $($Config.WEC_Server_FQDN) using certificate $($AuthCertificate.Thumbprint)"
  return (Get-WSManInstance winrm/config -ConnectionURI https://$($Config.WEC_Server_FQDN):5986/WSMAN -Authentication ClientCertificate -CertificateThumbprint $($AuthCertificate.Thumbprint))
}

function Test-LocalWinRMConfiguration {
  [CmdletBinding()]
  [OutputType([Boolean])]
  param(
    [switch] $Quiet
  )

  $WarningCount = 0
  $ErrorCount = 0

  try {
    $WinRmService = (Get-Service winrm 2>$null)

    if (!$WinRmService) {
      Write-Error "WinRM service doesn't exist"
      $ErrorCount++
    } else {
      Write-Verbose "WinRM Service exists"
    }

    if (! ($WinRmService.Status -eq "Running")) {
      Write-Error "WinRM service is not running"
      $ErrorCount++
    } else {
      Write-Verbose "WinRM Service is running"
    }

    $WinRmConfig = (Get-WSManInstance winrm/config)

    if (!$WinRmConfig) {
      Write-Error "Could not look up WinRM configuration"
      $ErrorCount++
    }
    else {
      Write-Verbose "WinRM configuration lookup succeeded."
      if (!$WinRmConfig.Client.Auth.Certificate) {
        Write-Error "WinRM client configuration does not have ClientCertificate authentication enabled on $($hostobj.Name).$($hostobj.Domain)."
        $ErrorCount++
      } else {
        Write-Verbose "WinRM client configuration has ClientCertificate authentication enabled."
      }

      ($http_listener = (Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Address="*";Transport="http"})) 2> $null | Out-Null

      if ($http_listener -and $http_listener.Enabled) {
        Write-Warning "$($hostobj.Name).$($hostobj.Domain) has an unsecured (HTTP) listener configured and enabled."
        $WarningCount++
      } else {
        Write-Verbose "$($hostobj.Name).$($hostobj.Domain) does not have a WinRM  http listener configured or enabled!  Good!"
      }
    }
  
    if (!$Quiet) { Write-Host "Test concluded. On Host $($hostobj.Name).$($hostobj.Domain) there were $WarningCount warnings and $ErrorCount errors with the WinRM configuration." }
  } catch {
    Write-Error "Could not look up winrm configuration on the local server"
    return $false
  }

  return $true
}