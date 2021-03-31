###
## Configure Windows Event Forwarding Policy
##
## Author: kmontgomery@covail.com
## Date: 2021-03-26
###

[CmdletBinding()]
param ([String]$go)

$domain_controller_policy_name = "ATDP_WindowsEventForwarding_DomainControllers"
$subscription_manager_policy_key = "HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
$security_event_log_sd_key = "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security"

function Configure-DomainControllerEventFowarding {
  [CmdletBinding()]
  [OutputType([Boolean])]
  param()

  ($hostobj = Get-WmiObject -Class Win32_ComputerSystem) 2>$null | out-null
  $dc_policy = (Get-Gpo -name $domain_controller_policy_name) 2>$null

  if (! $dc_policy) {
    Write-Output "INFO: Policy ${domain_controller_policy_name} does not yet exist, creating new policy..."
    $Error = $null
    ($dc_policy = New-Gpo -Name "${domain_controller_policy_name}" -Comment 'Windows Event Forwarding Policy for Domain Controllers for the COVAIL Attack Detector Platform') | Out-Null
    if ($Error) {
      $m = $Error[-1].Exception.Message
      Write-Error "ERROR: Could not create policy ${domain_controller_policy_name}: ${m}."
      return $false
    }
  }
  else {
    Write-Output "INFO: Policy ${domain_controller_policy_name} exists!"
  }

  ($subscription_manager_policy = Get-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$subscription_manager_policy_key" 2>$null) | Out-Null

  if (! ((Test-Path -Path $PSScriptRoot\atdp_subscription_data.psd1) 2>$null) -eq $true) {
    Write-Warning "WARN: No susbscription configuration data exists, please follow the prompts to provide the required information..."
    $null = Configure-ScriptData
  }

  $Config = Import-PowerShellDataFile $PSScriptRoot\atdp_subscription_data.psd1

  # $issuer_ca_thumbprint = (Get-ChildItem -Path cert:\LocalMachine\CA | where { $_.Subject -Match "CN=AtdpLab2-Root" } | foreach {$_.Thumbprint.ToLower()})
  # $domain_name = (Get-WmiObject Win32_ComputerSystem).Domain

  if (! $subscription_manager_policy) {
    Write-Output "INFO: Configuring WEF Subscritpion Manager Policy..."
    $subscription = "Server=HTTPS://$($Config.WEC_Server_FQDN):5986/wsman/SubscriptionManager/WEC,Refresh=60,IssuerCA=$($Config.Auth_Certificate_Issuer_CA_Thumbprint)"
    Write-Verbose "Subscription: ${subscription}"
    ($subscription_manager_policy = Set-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$subscription_manager_policy_key" -ValueName "1" -Type String -Value "${subscription}") | Out-Null
  } else {
    Write-Output "INFO: Subscription is currently set to: $($subscription_manager_policy.Value)"
  }

  # Configure security descriptor to allow NetworkService access to the Security Event Log

  ($security_event_log_sd_policy = Get-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$security_event_log_sd_key" 2>$null) | Out-Null
  if (! $security_event_log_sd_policy) {
    Write-Output "INFO: Configuring WEF Security Event Log SDDC Policy..."
    $value = 'O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1–5–32–573)(A;;0x1;;;S-1–5–20)'
    ($security_event_log_sd_policy = Set-GPRegistryValue -Name "$domain_controller_policy_name" -Key "$security_event_log_sd_key" -ValueName "ChannelAccess" -Type String -Value "${value}") | Out-Null
  } else {
    Write-Output "INFO: Security log SDDC already set to $($security_event_log_sd_policy.Value)"
  }

  # Ensure GPO is linked to Domain Controllers...
  $ou = "ou=Domain Controllers,dc=$($hostobj.Domain.replace('.',',dc='))"

  # Check for link
  $LinkCount = (((Get-GPInheritance -Target "${ou}").GpoLinks | where { $_.DisplayName -eq "$domain_controller_policy_name" }).Length)

  if ($LinkCount -lt 1) {
    try {
      Write-Output "INFO: linking ${domain_controller_policy_name} to ${ou}..."
      ($link = New-GPLink -Name "$domain_controller_policy_name" -Target "${ou}" -Enforced Yes) | Out-Null
    }
    catch {
      Write-Error "Could not create GPO Link: $_"
    }
  } else {
    Write-Output "INFO: ${domain_controller_policy_name} is already linked at ${ou}.."
  }

  return $true
}

function Configure-ScriptData {
  [CmdletBinding()]
  [OutputType([Boolean])]
  param()

  if (((Test-Path -Path $PSScriptRoot\atdp_subscription_data.psd1) 2>$null) -eq $true) {
    $Config = Import-PowerShellDataFile $PSScriptRoot\atdp_subscription_data.psd1
  }

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

  Get-ChildItem -path cert:\LocalMachine\CA | foreach { $Thumbprints += @{ Subject=$_.Subject; Thumbprint=$_.Thumbprint } }

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

  echo @"
@{
  WEC_Server_FQDN = "$($Config.WEC_Server_FQDN)"
  Auth_Certificate_Issuer_CA_Thumbprint = "$($Config.Auth_Certificate_Issuer_CA_Thumbprint)"
}
"@ | Out-File $PSScriptRoot\atdp_subscription_data.psd1 -Encoding utf8 -Force

  return $true
}


if (${go}.ToUpper() -eq "GO") {
  if (! ((Configure-DomainControllerEventFowarding -Verbose) -eq $true) ) { return $false }
}