<#
Mark Heitbrink
Cleanup-AdminCount.ps1

The goal is to Reset the AD USer Attribute "AdminCount" to "0", 
if the user is not a member of an group, protected by AdminSDHolder
There are some script around, but "some" people never heard of SID or RID, 
and are completly unaware, that there is more than englisch langauge around.

The AdminSDHolder protected groups are defined by Well-Known SIDs.
This script reports and works with the Well-Known SID and determines the displaynames.

Actual Version: Single Forest Single Domain
    ToDo:
       - Get Forest Domain SID for Schema Admins and Enterprise Admins

Appendix C: Protected Accounts and Groups in Active Directory
(AdminSDHolder)
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory

2.4.2.4 Well-Known SID Structures
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab

4.1.2.2 SID Filtering and Claims Transformation
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280

#############

Call Script in "Report Only" mode:
    .\Cleanup-AdminCount.ps1


Call Script in "Clean Up and repair" mode:
    .\Cleanup-AdminCount.ps1 -cleanup

#############
#>

Param (
    [Switch]
    $cleanup
    )

# 1. Determine AdminSDHolder protected objects
# 1.1 Get Domain SID and set BuiltIn

    $DomSID=(Get-ADDomain).DomainSID
    $BuiltIn="S-1-5-32"

# 1.2 Determine Protected Groups

    # BUILTIN_ADMINISTRATORS, S-1-5-32-544
    $BAdmins=Get-ADGroup "$BuiltIn-544"

    # ACCOUNT_OPERATORS, S-1-5-32-548
    $BAccounts=Get-ADGroup "$BuiltIn-548"

    # SERVER_OPERATORS, S-1-5-32-549
    $BServerOps=Get-ADGroup "$BuiltIn-549"

    # PRINTER_OPERATORS, S-1-5-32-550
    $BPrinterOps=Get-ADGroup "$BuiltIn-550"

    # BACKUP_OPERATORS, S-1-5-32-551
    $BBackupOps=Get-ADGroup "$BuiltIn-551"

    # REPLICATOR, S-1-5-32-552
    $BReplicator=Get-ADGroup "$BuiltIn-552"

    # ADMINISTRATOR, S-1-5-21-<machine>-500
    # Do not change Admincount on THE Administrator
    $Administrator=Get-ADUser "$DomSID-500"

    # KRBTGT, S-1-5-21-<domain>-502
    # Do not change Admincount on the krbtgt
    $krbtgt=Get-ADUser "$DomSID-502"

    # DOMAIN_ADMINS, S-1-5-21-<domain>-512
    $DomAdmins=Get-ADGroup "$DomSID-512"

    # DOMAIN_DOMAIN_CONTROLLERS, S-1-5-21-<domain>-516
    $DomCon=Get-ADGroup "$DomSID-516"

    # SCHEMA_ADMINISTRATORS, S-1-5-21-<root-domain>-518
    $SchemaAdmins=Get-ADGroup "$DomSID-518"

    # ENTERPRISE_ADMINS, S-1-5-21-<root-domain>-519
    $EntAdmins=Get-ADGroup "$DomSID-519"

    # READONLY_DOMAIN_CONTROLLERS, S-1-5-21-<domain>-521
    $RODC=Get-ADGroup "$DomSID-521"

    # KEY_ADMINS, S-1-5-21-<domain>-526
    $KeyAdmins=Get-ADGroup "$DomSID-526"

    # ENTERPRISE_KEY_ADMINS, S-1-5-21-<domain>-527
    $EntKeyAdmins=Get-ADGroup "$DomSID-527"

# 1.3 All AdminSDHolder Objects
    $AllAdminSD=
    $BAdmins.Name,
    $BAccounts.Name,
    $BServerOps.Name,
    $BPrinterOps.Name,
    $BBackupOps.Name,
    $BReplicator.Name,
    $Administrator.Name,
    $krbtgt.Name,
    $DomAdmins.Name,
    $DomController.Name,
    $SchemaAdmins.Name,
    $EntAdmins.Name,
    $RODC.Name,
    $KeyAdmins.Name,
    $EntKeyAdm.Name

# 2. Collect all Users, where AdminCount = 1
    $AllAdminCount=Get-ADUser -Filter {AdminCount -eq "1"}

# 2.1 Report and Process all Users, where AdminCount = 1
    foreach ($User in $AllAdminCount){
      # Collect Group Memberships of the Users
      $AllGroups=(Get-ADPrincipalGroupMembership $User).Name
      # Combine User Groups and Protected Groups
      $AllTogether=$($AllGroups;$AllAdminSD)
      # Find Duplictes/Matches
      $Duplicates = $AllTogether | Group-Object | ?{$_.Count -gt 1} 
      
      # Exclude Administrator (RID-500) and krbtgt from Processing
      if (($user.Name -eq $Administrator.Name) -or ($User.Name -eq $krbtgt.Name)) {
        Write-Host $User.Name: Leave as it is -ForegroundColor Gray
        } Else {
        if ($Duplicates) {
            # Report Membership of AdminSDHolder Protected Groups
            Write-Host $User.Name: $Duplicates.Name -ForegroundColor Green
            } Else {
            Write-Host $User.Name: You should remove orphaned AdminCount = 1 -ForegroundColor Red

            # Remove AdminCount and enable ACL inheritance, 
            # Object is no longer protected by sdprop/AdminSDHolder
            # and the permissions will be resettet to the OU Level, where
            # the object resides.

# 2.2 Cleanup All Users, where AdminCount = 1
            if ($cleanup) {
            Write-Host $User.Name: Cleaned -ForegroundColor Cyan
            # Reset admincount to "not set"
            Set-ADUser -Identity $User -Clear adminCount               
            # Read ACL, set new ACL and write back ACL
            $CN=$User.DistinguishedName
            $GetAcl=Get-Acl -path AD:$cn
            # .SetAccessRuleProtection =  Boolean (value,value)
            # 1 value "isprotected" = $false (Enable Inheritance)
            # 2 value "preserveInheritance" = $true (inherite ACL)
            # 2 value will be ignored, if 1 value = $false, but is mandatory
            $GetAcl.SetAccessRuleProtection($false,$true)
            Set-Acl -Path AD:$CN -AclObject $GetAcl
            }
        }
    }
}
