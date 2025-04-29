# Cleanup-AdminCount
A language independent(!) Powershell Script to remove orphaned AdminCounts on User objects in AD and enable ACL inheritance. Repair User Accounts, protected by sdprop/AdminSDHolder process in Active Directory, that are no longer Member of Protected Groups

**Call Script in "Report Only" mode:**
```
.\Cleanup-AdminCount.ps1
```
**Call Script in "Clean Up and repair" mode:**
```
.\Cleanup-AdminCount.ps1 -cleanup
```

## Depending Ressource
Appendix C: Protected Accounts and Groups in Active Directory
https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory

2.4.2.4 Well-Known SID Structures
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab

4.1.2.2 SID Filtering and Claims Transformation
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280

