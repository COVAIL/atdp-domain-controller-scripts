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

## SET GLOBAL ARGUMENTS
$principal = Get-ADDomain | select -ExpandProperty distinguishedname
$principal2 = "CN=Configuration,$principal"
$principal3 = "CN=Schema,CN=Configuration,$principal"
$adminSDHolder = Get-ADObject -Filter "name -eq 'adminsdholder'" | select -ExpandProperty distinguishedname
 
$flags = 'Success','Failure';
$AuditGroup = "Domain Users" #'Authenticated Users' #'Guest'; # NOTE: THIS ARGUMENT CAN BE CHANGED TO 'Domain Uesrs' SO THAT ACEs ARE WRITTEN AND APPLIED
$Flag = $true #$true results in ACEs being added, $false results in ACEs being removed
 
 
## REMOVE ALL AUDIT SACLS FROM DOMAIN!!!!!
$acl = Get-Acl -Path AD:\$principal -Audit;
$acl.GetAuditRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | Foreach-Object { $acl.RemoveAuditRule($_); }
Set-Acl -Path AD:\$principal -AclObject $acl
$acl = Get-Acl -Path AD:\$principal2 -Audit;
$acl.GetAuditRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | Foreach-Object { $acl.RemoveAuditRule($_); }
Set-Acl -Path AD:\$principal2 -AclObject $acl
 
 
## FUNCTION TO ADD OR REMOVE SACLS
function Add-ToSACL {
    [CmdletBinding()]
    Param (
        [Parameter(Position=0,Mandatory = $True, HelpMessage='Enter the distinguished name of the target to which the SACL will be applied.')]
        [Alias('PrincipalDistinguihsedName')]
        $Principal,
 
        [Parameter(Mandatory = $False, HelpMessage='Enter the Security.principal.NTAccount to which the ACEs will apply. Defaults to Domain Users')]
        $AppliesTo = 'Domain Users',
 
        [Parameter(Mandatory=$True, HelpMessage='Enter the System.DirectoryServices.ActiveDirectoryRight you wish to audit.')]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $Right,
 
        [Parameter(Mandatory = $False, HelpMessage='Enter the desired System.Security.AccessControl.AuditFlags. Defaults to Success,Failure')]
        $AuditFlag = ('Success','Failure'),
 
        [Parameter(Mandatory = $True, HelpMessage='Enter the class guid of the object type you wish to audit. Accepts an array')]
        $ObjectType,
 
        [Parameter(Mandatory = $False, HelpMessage='Enter the desired System.DirectoryServices.ActiveDirectorySecurityInheritance. Defaults to All')]
        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        $InheritanceType = 'All',
 
        [Parameter(Mandatory = $True, HelpMessage='Enter the class guid of the object type you wish to enherit the SACL')]
        $InheritedObjectType,
 
        [Parameter(Mandatory = $False, HelpMessage='Default is true, add to SACL. Set to false to remove ACEs from SACL')]
        [Boolean]
        $AddAuditRule = $True
    )
    <#EXAMPLE
    # SETTING SACLES FOR DCSYNC REPLICATION EXTENDED RIGHTS
    $principal = Get-ADDomain | select -ExpandProperty distinguishedname
    $adright = 'ExtendedRight'
    $ds_rep_get_changes_guid = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    $ds_rep_get_changes_all_guid = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
    $ds_rep_get_changes_filtered_set_guid = [guid]"89e95b76-444d-4c62-991a-0facbeda640c";
    $null_guid = [guid]'00000000-0000-0000-0000-000000000000'
    $rights_guids = $ds_rep_get_changes_guid, $ds_rep_get_changes_all_guid, $ds_rep_get_changes_filtered_set_guid;
     
    # Add ACEs to SACL
    Add-ToSACL -Principal $principal -Right $adright -ObjectType $rights_guids -InheritedObjectType $null_guid
    # Remove ACEs from SACL
    Add-ToSACL -Principal $principal -Right $adright -ObjectType $rights_guids -InheritedObjectType $null_guid -AddAuditRule $false
    #>
    Begin {
        $AppliesTo = [Security.principal.NTAccount]$AppliesTo
        $Right = [System.DirectoryServices.ActiveDirectoryRights]$Right
        $AuditFlag = [System.Security.AccessControl.AuditFlags]$AuditFlag
        $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType
        $InheritedObjectType = [Guid]$InheritedObjectType
    }
    Process {
        foreach($Target in $ObjectType){
            $Acl = Get-Acl -Path AD:\$Principal -Audit
            $PrintFlags = ($AuditFlag -join ",")
            $AuditGuid = [Guid]$Target
            # Write-Host "Calling System.directoryServices.ActiveDirectoryAuditRule($AppliesTo, $Right, $AuditFlag, $AuditGuid, $InheritanceType, $InheritedObjectType)"
            $Ace = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($AppliesTo, $Right, $AuditFlag, $AuditGuid, $InheritanceType, $InheritedObjectType)
            if($AddAuditRule) {
                Write-Host "Modifying the SACL of $Principal.`nAdding a $PrintFlags ACE to $Right $AuditGuid.`nThis ACE applies to $AppliesTo and will be inherited by $InheritanceType $InheritedObjectType class objects.`n" -ForegroundColor Green
                $Acl.AddAuditRule($Ace)
            } else {
                Write-Host "Modifying the SACL of $Principal.`nRemoving a $PrintFlags ACE to $Right $AuditGuid.`nThis ACE applied to $AppliesTo and was inherited by $InheritanceType $InheritedObjectType class objects.`n" -ForegroundColor Red
                $Acl.RemoveAuditRule($Ace)
            }
            Set-Acl -Path AD:\$Principal -AclObject $Acl;
       }
    }
}
 
 
## EXTENDED RIGHTS GUIDS
$ds_rep_get_changes_guid = [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
$ds_rep_get_changes_all_guid = [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
$ds_rep_get_changes_filtered_set_guid = [guid]"89e95b76-444d-4c62-991a-0facbeda640c";
$user_force_change_password = [guid]"00299570-246d-11d0-a768-00aa006e0529";
$write_validated_spn = [guid]'f3a64788-5306-11d1-a9c5-0000f80367c1';
 
## Class GUIDs (https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all)
$domain_dns_class = [guid]'19195a5b-6da0-11d0-afd3-00c04fd930c9'
$computer_class = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
$subnet_class = [guid]'b7b13124-b82e-11d0-afee-0000f80367c1'
$group_class = [guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'
$trust_class = [guid]'bf967ab8-0de6-11d0-a285-00aa003049e2'
$user_class = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
$site_class = [guid]'bf967ab3-0de6-11d0-a285-00aa003049e2'
$gpo_class = [guid]'f30e3bc2-9ff0-11d1-b603-0000f80367c1'
$ou_class = [guid]'bf967aa5-0de6-11d0-a285-00aa003049e2'
 
 
## Property GUIDs
$object_class = [guid]'bf9679e5-0de6-11d0-a285-00aa003049e2'
$object_category = [guid]'26d97369-6070-11d1-a9c6-0000f80367c1'
$admin_count = [guid]'bf967918-0de6-11d0-a285-00aa003049e2'
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
$nt_security_descriptor = [guid]'bf9679e3-0de6-11d0-a285-00aa003049e2'
$spn_guid = [guid]'f3a64788-5306-11d1-a9c5-0000f80367c1'
$gplink_guid = [guid]'f30e3bbe-9ff0-11d1-b603-0000f80367c1'
$gppath_guid = [guid]'f30e3bc1-9ff0-11d1-b603-0000f80367c1'
$user_password = [guid]'bf967a6e-0de6-11d0-a285-00aa003049e2'
$user_unicode_password = [guid]'bf9679e1-0de6-11d0-a285-00aa003049e2'
$allowed_to_act_on_behalf_of = [guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
$user_account_control = [guid]'bf967a68-0de6-11d0-a285-00aa003049e2'
 
 
## SETTING SACL FOR WRITING TO ADMINSDHOLDER not ready
#Add-ToSACL -Principal $adminSDHolder -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $null_guid -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
#Add-ToSACL -Principal $adminSDHolder -AppliesTo 'Authenticated Users' -Right 'WriteOwner' -ObjectType $null_guid -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
 
 
## SETTING SACLs FOR NT-SECURITY-DESCRIPTOR: [Owner, DACL] set and SACL
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'ReadControl' -ObjectType $null_guid -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'AccessSystemSecurity' -ObjectType $null_guid -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteDACL' -ObjectType $null_guid -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteOwner' -ObjectType $null_guid -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'Self' -ObjectType $null_guid -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
 
 
## SETTING SACLs EXTENDED RIGHTS
$rights_guids = $ds_rep_get_changes_guid, $ds_rep_get_changes_all_guid, $ds_rep_get_changes_filtered_set_guid,$user_force_change_password;
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'ExtendedRight' -ObjectType $rights_guids -InheritanceType 'All' -InheritedObjectType $null_guid -AddAuditRule $Flag
 
 
## SETTING SACLs FOR USERS
$properties = $sam_account_name,$distinguished_name,$object_sid,$object_guid,$admin_count,$member,$member_of,$spn_guid,$user_account_control,$nt_security_descriptor
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $user_class -AddAuditRule $Flag
$properties = $properties + $user_password + $user_unicode_password
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $user_class -AddAuditRule $Flag
 
 
## SETTING SACLs FOR COMPUTERS
$properties = $sam_account_name,$attribute_name,$dns_name,$distinguished_name,$object_sid,$object_guid,$spn_guid,$allowed_to_act_on_behalf_of,$nt_security_descriptor
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $computer_class -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $computer_class -AddAuditRule $Flag
 
 
## SETTING SACLs FOR OUs
$properties = $sam_account_name,$distinguished_name,$object_sid,$object_guid,$gplink_guid,$admin_count,$member,$member_of,$nt_security_descriptor
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $ou_class -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $ou_class -AddAuditRule $Flag
 
 
## SETTING SACLs FOR GROUPS
$properties = $sam_account_name,$distinguished_name,$object_sid,$object_guid,$admin_count,$member,$member_of,$nt_security_descriptor
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $group_class -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $group_class -AddAuditRule $Flag
 
 
## SETTING SACLs FOR TRUSTS
$properties = $trust_direction,$trust_partner,$trust_type,$trust_attributes,$distinguished_name,$object_sid,$object_guid,$nt_security_descriptor
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $trust_class -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $trust_class -AddAuditRule $Flag
 
 
## SETTING SACLs FOR GPOs
$properties = $common_name,$distinguished_name,$member,$attribute_name,$object_sid,$object_guid,$gplink_guid,$gppath_guid,$nt_security_descriptor
Add-ToSACL -Principal $principal -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $gpo_class -AddAuditRule $Flag
Add-ToSACL -Principal $principal -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $gpo_class -AddAuditRule $Flag
 
 
## SETTING SACLs FOR SUBNET
$properties = $distinguished_name,$attribute_name,$object_sid,$object_guid,$gplink_guid,$object_category,$nt_security_descriptor
Add-ToSACL -Principal $principal2 -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $subnet_class -AddAuditRule $Flag
Add-ToSACL -Principal $principal2 -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $subnet_class -AddAuditRule $Flag
 
 
## SETTING SACLs FOR SITE
$properties = $distinguished_name,$attribute_name,$object_sid,$object_guid,$gplink_guid,$object_class,$nt_security_descriptor
Add-ToSACL -Principal $principal2 -AppliesTo $AuditGroup -Right 'ReadProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $site_class -AddAuditRule $Flag
Add-ToSACL -Principal $principal2 -AppliesTo 'Authenticated Users' -Right 'WriteProperty' -ObjectType $properties -InheritanceType 'Descendents' -InheritedObjectType $site_class -AddAuditRule $Flag
