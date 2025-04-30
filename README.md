# Cleanup-AdminCount
A <ins>**language independent(!)**</ins> Powershell Script to remove orphaned AdminCount=1 on User objects in Active Directory and enable ACL inheritance from parent OU.
Repair/Cleanup User Accounts, protected by sdprop/AdminSDHolder process in Active Directory, that are no longer Member of one of the Protected Groups.

The Script doesn´t work initialliy with the displayname of the the group. The problem is, that´s a localized name and there is **more than** english. 

The script uses the best common denominator: The Well-Known SID. Simple as that.
The report of group membership is the localized version of the group.  

Groups protected by sdprop (AdminSDHolder) process.  
- Account Operators
- Administrator
- Administrators
- Backup Operators
- Domain Admins
- Domain Controllers
- Enterprise Admins
- Enterprise Key Admins
- Key Admins
- Krbtgt
- Print Operators
- Read-only Domain Controllers
- Replicator
- Schema Admins
- Server Operators

**Call Script in "Report Only" mode:**
```
.\Cleanup-AdminCount.ps1
```
**Call Script in "Clean Up and repair" mode:**
```
.\Cleanup-AdminCount.ps1 -cleanup
```
**Running Script - Both Modi**
![grafik](https://github.com/user-attachments/assets/a66cbc64-32e7-42e4-9cd7-f4499c9f2b34)

## Background / Information / Microsoft Ressources
[Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

[2.4.2.4 Well-Known SID Structures](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)

[4.1.2.2 SID Filtering and Claims Transformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)

