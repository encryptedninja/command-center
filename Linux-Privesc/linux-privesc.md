# Windows Privilege Escalation
## //cheat-sheet

**[Back to Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**

### Resources:

* **[g0tm1lk](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)**
* **[hacktricks](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist)**
* **[sushant747 OSCP-guide](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)**

### Automated privesc tools:

* **[linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)**
* **[linenum](https://github.com/rebootuser/LinEnum)**
* **[linenumsuggester](https://github.com/mzet-/linux-exploit-suggester)**
* **[linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)**

### Escalation path: Kernel exploits
#### Kernel exploits are very straight forward. We hunt down what version of kernel is running on the target system and then we exploit it.

* **[resource: lucyoa/kernerl-exploit](https://github.com/lucyoa/kernel-exploits)**

* chek kernel version on target system: `uname -a`
* compile dirty c0w.c first `gcc -phthread c0w.c -o cow`
* use dirty c0w on target machine `./cow`
* c0w output: ***Backing up /usr/bin/passwd to /tmp/bak***
* type in: `passwd` and you're **root**

### Escalation path: Password and file permissions

#### Escalation via stored passwords:

* see history if possible, if someone connected to a mysql database with their credentials for example it will show up in there, use command `history`
* cat out the `cat .bash_history` as well
* you can also try using the ***history*** command with ***grep*** to grep for the password: `histroy | grep passwd`
* `ps aux` to see processes
* `w` to see who's logged in 
* when asked for a password on the system if you see asterisks while typing out the password in terminal that's a very specific version of ***sudo***, that's usually the **.pwfeedback** is being set. **env_reset.pwfeedback** is being reset.
* ***cat*** out the ****.ovpn*** file to check for credentials or references: `cat myvpn.ovpn` shows that the password is coming from the ***/etc/openvpn/auth.txt*** so we can just cat that file out for credentials

#### Escalation via weak file permissions:

* `ls -la /etc/passwd` and `ls -la /etc/shadow` if you can access both and cat them out we can use ***john*** or other similar tools to crack those passwords
* passwd file doesn't have any passwords in it (back in the day it was) , it helps us to ID the users
* **x**  is a placeholder in it for the hash which contains the password from the shadow file
* if we can modify /etc/passwd the x in the file we could become root,
like delete it, if there's no placeholder we can just switch to root user without a password or change it to 0
* we can change the hash to one where we know the password and become root like that

#### Escalation via ssh keys:

* `find / -name authorized_keys 2>/dev/null`
* `find / -name id_rsa 2>/dev/null`
* once the key was found copy it to your machine into a file and don't forget to `chmod 600 id_rsa` to be able to use it to log in via ssh
* `ssh -i id_rsa root@<target IP>`

### Escalation path: sudo
