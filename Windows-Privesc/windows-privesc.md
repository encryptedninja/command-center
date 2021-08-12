**[Back to Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**

# Windows Privilege Escalation
## //cheat-sheet

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


