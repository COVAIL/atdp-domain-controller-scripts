###
# Copyright © 2021, Columbus Collaboratory LLC d/b/a Covail™ – All Rights Reserved
 
# This code is confidential Covail™ property.  This software and its code
# may only be used by Covail™ for internal business purposes.
# For more information consult the Covail™ Master Services Agreement and/or SOW
# that governed the development of this software and code.
 
# Author: bbishop@covail.com
# Date: 2021-03-31
###

#Requires -Version 4.0

# SET THE ARGUMENTS
$principal = Get-ADDomain | select -ExpandProperty distinguishedname
$flags = 'Success','Failure';
$AuditGroup =  'Domain Users' # THIS ARGUMENT CAN BE CHANGED TO 'Guest' SO THAT ACEs ARE WRITTEN BUT NOT APPLIED
$remove = $false # Set this to $true to remove previously configured ACEs, rather than set them
$acl = Get-Acl -Path AD:$principal -Audit;
 
# REMOVE ALL AUDIT SACLS FROM DOMAIN!!!!!
# THIS CANNOT BE UNDONE
# $acl.GetAuditRules($True, $False, [System.Security.Principal.SecurityIdentifier]) | Foreach-Object { $acl.RemoveAuditRule($_); }
# Set-Acl -Path AD:$principal $acl
# $acl = Get-Acl -Path AD:$principal -Audit;
 
# SETTING SACLS FOR DCSYNC REPLICATION EXTENDED RIGHTS
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
    $inheritedObjectType = [guid]'00000000-0000-0000-0000-000000000000';
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:$principal -AclObject $acl;
}
  
# Property GUIDs
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
 
# Class GUIDs
$user_class = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
$computer_class = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
$ou_class = [guid]'bf967aa5-0de6-11d0-a285-00aa003049e2'
$group_class = [guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'
$trust_class = [guid]'bf967ab8-0de6-11d0-a285-00aa003049e2'
$gpo_class = [guid]'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
 
# SETTING SACLS FOR OBJECT ACCESS
$adright = 'ReadProperty'
 
# Set SACLs for users
$properties = $sam_account_name,$object_sid,$object_guid,$distinguished_name,$display_name,$attribute_name
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $user_class
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:$principal -AclObject $acl;
}
 
# Set SACLs for computers
$properties = $sam_account_name,$dns_name,$object_sid,$object_guid,$distinguished_name,$display_name,$attribute_name
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $computer_class
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:$principal -AclObject $acl;
}
 
# Set SACLs for ou
$properties = $object_sid,$object_guid,$distinguished_name,$display_name,$attribute_name
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $ou_class
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:$principal -AclObject $acl;
}
 
# Set SACLs for groups
$properties = $sam_account_name,$member,$member_of,$object_sid,$object_guid,$distinguished_name,$display_name,$attribute_name
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $group_class
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:$principal -AclObject $acl;
}
 
# Set SACLs for trust
$properties = $trust_direction,$trust_partner,$trust_type,$trust_attributes,$object_sid,$object_guid,$distinguished_name,$display_name,$attribute_name
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $trust_class
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:$principal -AclObject $acl;
}
 
# Set SACLs for gpo
$properties = $object_sid,$object_guid,$distinguished_name,$display_name,$attribute_name,$common_name,$member,$member_of
foreach($property_guid in $properties){
    $appliesTo = [Security.principal.NTAccount]$AuditGroup;
    $rights = [System.DirectoryServices.ActiveDirectoryRights]$adright;
    $auditFlags = [System.Security.AccessControl.AuditFlags]$flags;
    $objectType = $property_guid;
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Descendents';
    $inheritedObjectType = $gpo_class
    $ace = New-Object System.directoryServices.ActiveDirectoryAuditRule($appliesTo, $rights, $auditFlags, $objectType, $inheritanceType, $inheritedObjectType);
    if($remove) {
        $acl.RemoveAuditRule($ace)
    } else {
        $acl.AddAuditRule($ace)
    }
    Set-Acl -Path AD:$principal -AclObject $acl;
}