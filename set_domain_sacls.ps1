###
## Copyright © 2022, GoSecure, Inc. – All Rights Reserved
## 
## This code is confidential GoSecure, Inc. property.  This software and its code
## may only be used by GoSecure, Inc. for internal business purposes.
## For more information consult the GoSecure, Inc. Master Services Agreement and/or SOW
## that governed the development of this software and code.
 
# Author: bbishop@covail.com / kmontgomery@gosecure.net
# Date: 2022-05-11
###
# NOTE: should be run from a domain-joined computer with RSAT tools installed, .NET framework 4.6.2+ by a user in the Domain Admins group.
###

#Requires -Version 4.0

$NetFrameworkRelease = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release

if ($NetFrameworkRelease -lt 394802) {
     Write-Warning "WARN: .NET Framework 4.6.2+ is not installed, this script may not run properly"
     Exit 1
}

# SET THE ARGUMENTS
$principal = Get-ADDomain | select -ExpandProperty distinguishedname
$flags = 'Success','Failure';
$AuditGroup =  'Guest' #'Guest' #"Domain Users"; # NOTE: THIS ARGUMENT CAN BE CHANGED TO 'Domain Uesrs' SO THAT ACEs ARE WRITTEN AND APPLIED
$remove = $false
  
# REMOVE ALL AUDIT SACLS FROM DOMAIN!!!!!
$acl = Get-Acl -Path AD:\$principal -Audit;
$acl.GetAuditRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | Foreach-Object { $acl.RemoveAuditRule($_); }
Set-Acl -Path AD:\$principal $acl
$acl = Get-Acl -Path AD:\$principal -Audit;
$acl.GetAuditRules($False, $True, [System.Security.Principal.SecurityIdentifier]) | Foreach-Object { $acl.RemoveAuditRule($_); }
Set-Acl -Path AD:\$principal $acl
$acl = Get-Acl -Path AD:\$principal -Audit;
 
# Property GUIDs
$object_class = [guid]'bf9679e5-0de6-11d0-a285-00aa003049e2'
$object_category = [guid]'26d97369-6070-11d1-a9c6-0000f80367c1'
$user_account_control = [guid]'bf967a68-0de6-11d0-a285-00aa003049e2'
$admin_count = [guid]'bf967918-0de6-11d0-a285-00aa003049e2'
$nt_security_descriptor = [guid]'bf9679e3-0de6-11d0-a285-00aa003049e2'
$security_principal = [guid]'bf967ab0-0de6-11d0-a285-00aa003049e2'
$sam_account_name = [guid]'3e0abfd0-126a-11d0-a060-00aa006c33ed'
$distinguished_name = [guid]'bf9679e4-0de6-11d0-a285-00aa003049e2'
$display_name = [guid]' bf96791a-0de6-11d0-a285-00aa003049e2'
$common_name = [guid]'bf96793f-0de6-11d0-a285-00aa003049e2'
$object_sid = [guid]'bf9679e8-0de6-11d0-a285-00aa003049e2'
$object_guid = [guid]'bf9679e7-0de6-11d0-a285-00aa003049e2'
$member_of = [guid]'bf967991-0de6-11d0-a285-00aa003049e2'
$member = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
$dns_name = [guid]'72e39547-7b18-11d1-adef-00c04fd8d5cd'
$attribute_name = [guid]'bf967a0e-0de6-11d0-a285-00aa003049e2'
$trust_direction = [guid]'bf967a5c-0de6-11d0-a285-00aa003049e2'
$trust_partner = [guid]'bf967a5d-0de6-11d0-a285-00aa003049e2'
$trust_type = [guid]'bf967a60-0de6-11d0-a285-00aa003049e2'
$trust_attributes = [guid]'80a67e5a-9f22-11d0-afdd-00c04fd930c9'
$null_guid = [guid]'00000000-0000-0000-0000-000000000000'

# Class GUIDs
# https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all
$user_class = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
$computer_class = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
$ou_class = [guid]'bf967aa5-0de6-11d0-a285-00aa003049e2'
$group_class = [guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'
$trust_class = [guid]'bf967ab8-0de6-11d0-a285-00aa003049e2'
$gpo_class = [guid]'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
$subnet_class = [guid]'b7b13124-b82e-11d0-afee-0000f80367c1'
$site_class = [guid]'bf967ab3-0de6-11d0-a285-00aa003049e2'

# SETTING SACLs FOR DCSYNC REPLICATION EXTENDED RIGHTS
$adright = 'ExtendedRight'
$ds_rep_get_changes_guid = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
$ds_rep_get_changes_all_guid = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
$ds_rep_get_changes_filtered_set_guid = [guid]"89e95b76-444d-4c62-991a-0facbeda640c";
$rights_guids = $ds_rep_get_changes_guid, $ds_rep_get_changes_all_guid, $ds_rep_get_changes_filtered_set_guid;
  
foreach($rightguid in $rights_guids){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = [guid]$rightguid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'All';
    $inheritedObjectType = $null_guid;
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal -AclObject $acl;
}

# SETTING SACL FOR NT-SECURITY-DESCRIPTOR READS
$appliesTo = [Security.principal.NTAccount]$AuditGroup;
$rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
$auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
$objectType = $null_guid;
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'SelfAndChildren';
$inheritedObjectType = $null_guid
Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
$ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
if($remove) {
    $acl.RemoveAuditRule($ace)
} else {
    $acl.AddAuditRule($ace)
}
Set-Acl -Path AD:\$principal -AclObject $acl;
  
# SETTING SACLS FOR OBJECT ACCESS
$adright = 'ReadProperty'
  
# Set SACLs for users
$acl = Get-Acl -Path AD:\$principal -Audit;
$properties = $sam_account_name,$distinguished_name,$object_sid,$object_guid,$admin_count,$member,$member_of,$nt_security_descriptor,$security_principal#,$null_guid,$user_account_control
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    if($property_guid -in ($null_guid,$nt_security_descriptor,$user_account_control,$security_principal)) {
        #$rights = [System.DirectoryServices.ActiveDirectoryRights]'AccessSystemSecurity'
        $rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
    } else {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    }
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $user_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal -AclObject $acl;
}

<#
#set SACL for lastlogon write
$acl = Get-Acl -Path AD:\$principal -Audit;
$appliesTo = [Security.principal.NTAccount]'Everyone';
$rights = [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty'
$auditFlags = [System.Security.AccessControl.AuditFlags]$flags
$objectType = [guid]'bf967997-0de6-11d0-a285-00aa003049e2'
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents'
$inheritedObjectType = $user_class
Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
$ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
if($remove) {
    $acl.RemoveAuditRule($ace)
} else {
    $acl.AddAuditRule($ace)
}
Set-Acl -Path AD:\$principal -AclObject $acl;
 
$acl = Get-Acl -Path AD:\$principal -Audit;
$appliesTo = [Security.principal.NTAccount]'Everyone';
$rights = [System.DirectoryServices.ActiveDirectoryRights]'Self'
$auditFlags = [System.Security.AccessControl.AuditFlags]$flags
$objectType = [guid]'bf967997-0de6-11d0-a285-00aa003049e2'
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents'
$inheritedObjectType = $user_class
Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
$ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
if($remove) {
    $acl.RemoveAuditRule($ace)
} else {
    $acl.AddAuditRule($ace)
}
Set-Acl -Path AD:\$principal -AclObject $acl;
#>
  
# Set SACLs for computers
$properties = $sam_account_name,$attribute_name,$dns_name,$distinguished_name,$object_sid,$object_guid,$nt_security_descriptor,$security_principal
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    if($property_guid -in ($null_guid,$nt_security_descriptor,$security_principal)) {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
    } else {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    }
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $computer_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal -AclObject $acl;
}
  
# Set SACLs for ou
$properties = $attribute_name,$distinguished_name,$object_sid,$object_guid,$nt_security_descriptor,$security_principal
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    if($property_guid -in ($null_guid,$nt_security_descriptor,$security_principal)) {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
    } else {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    }
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $ou_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal -AclObject $acl;
}
  
# Set SACLs for groups
$properties = $sam_account_name,$distinguished_name,$object_sid,$object_guid,$admin_count,$member,$member_of#,$nt_security_descriptor,$security_principal
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    if($property_guid -in ($null_guid,$nt_security_descriptor,$security_principal)) {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
    } else {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    }
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $group_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal -AclObject $acl;
}
  
# Set SACLs for trust
$properties = $trust_direction,$trust_partner,$trust_type,$trust_attributes,$distinguished_name,$object_sid,$object_guid#,$nt_security_descriptor,$security_principal
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    if($property_guid -eq $null_guid) {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
    } else {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    }
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $trust_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal -AclObject $acl;
}
  
# Set SACLs for gpo
$properties = $common_name,$distinguished_name,$member,$attribute_name,$object_sid,$object_guid#,$nt_security_descriptor,$security_principal
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    if($property_guid -eq $null_guid) {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]'ReadControl'
    } else {
        $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    }
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $gpo_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal -AclObject $acl;
}
 
# Set SACLs for subsets
$principal2 = "CN=Configuration,$principal"
$acl = Get-Acl -Path AD:\$principal2 -Audit
$properties = $distinguished_name,$attribute_name,$object_sid,$object_guid,$object_category
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $subnet_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal2 -AclObject $acl;
}
 
# Set SACLs for sites
$acl = Get-Acl -Path AD:\$principal2 -Audit
$properties = $distinguished_name,$attribute_name,$object_sid,$object_guid,$object_class
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $site_class
    Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType)"
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:\$principal2 -AclObject $acl;
}
