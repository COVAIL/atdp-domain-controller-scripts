###
## Copyright © 2022, GoSecure, Inc. – All Rights Reserved
## 
## This code is confidential GoSecure, Inc. property.  This software and its code
## may only be used by GoSecure, Inc. for internal business purposes.
## For more information consult the GoSecure, Inc. Master Services Agreement and/or SOW
## that governed the development of this software and code.
###
## Configure Windows Event Forwarding Policy
##
## Author: kmontgomery@gosecure.net
## Date: 2021-03-26
###

#Requires -Version 4.0

[CmdletBinding()]
param()

Import-Module -Name (Join-Path $PSScriptRoot event_forwarding_module_functions.psm1 -Resolve) -WarningAction SilentlyContinue
Configure-DomainControllerEventFowarding
