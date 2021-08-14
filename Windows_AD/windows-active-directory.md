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

### Initial Attack Vectors

* first we have to find a way in to the network
* how to abuse features of Windows
* support article: **[Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition)](https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)**

#### LLMNR poisoning

* **LINK LOCAL MULTICAST NAME RESOLUTION**
* used to identify hosts when DNS fails to do so
* previously ***NBT-NS***
* **key flaw is** that the the service utilize a user's username and  NTLMv2 hash when approprietly responded to
* when we respond to this service it responds back to us with a username and a NTLMv2 password hash
* user types in something misspelled, server send us a broadcast message, we listen ***men in the middle*** attack, we respond yes and capture the username and hash then forward the request to the server. **responder** will help us with that, which is a tool from **Impacket**
* run **responder** first thing in the morning or when people come back from lunch because it needs some traffic

##### Responder:

* `python Responder.py -l tun0 -rdw`



