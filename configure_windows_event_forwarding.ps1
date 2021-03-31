###
## Configure Windows Event Forwarding Policy
##
## Author: kmontgomery@covail.com
## Date: 2021-03-26
###

[CmdletBinding()]
param()

Import-Module -Name (Join-Path $PSScriptRoot module_functions.psm1 -Resolve) -WarningAction SilentlyContinue
Configure-DomainControllerEventFowarding
