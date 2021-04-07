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

Import-Module -Name (Join-Path $PSScriptRoot event_forwarding_module_functions.psm1 -Resolve) -WarningAction SilentlyContinue
Get-WecConfiguration